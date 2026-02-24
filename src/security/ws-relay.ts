/**
 * WebSocket Relay for the Secrets Proxy
 *
 * Provides a WebSocket relay endpoint that the container can connect to for
 * reaching the Discord gateway (and similar WSS targets) without the proxy
 * needing to perform TLS termination on the container side.
 *
 * Flow:
 *   1. Container opens WS connection to ws://proxy:port/ws-relay
 *      with X-WS-Target-URL: wss://gateway.discord.gg/?v=10 in the upgrade request.
 *   2. Proxy authenticates the request via X-Proxy-Token header.
 *   3. Proxy opens a WSS connection to the real target.
 *   4. Proxy relays frames bidirectionally:
 *      - Container→Discord: text frames are scanned for {{CONFIG:...}} placeholders
 *        and replaced with real secrets before forwarding.
 *      - Discord→Container: frames forwarded as-is.
 *
 * The container→proxy leg is plain WS on the internal Docker network (no TLS needed).
 * The proxy→Discord leg is TLS (WSS). No self-signed certs or trust-store changes needed.
 */
import type http from "node:http";
import WebSocket, { WebSocketServer } from "ws";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { isDomainAllowed } from "./secrets-proxy-allowlist.js";

const logger = createSubsystemLogger("security/ws-relay");

/** Max text frame size to inspect for placeholders (bytes). */
const MAX_INSPECT_SIZE = 64 * 1024; // 64 KB

export type FrameTransformer = (text: string) => Promise<string>;

/**
 * Install a WebSocket server on the existing HTTP server.
 *
 * Handles upgrades to /ws-relay only — all other upgrade paths are rejected.
 * This attaches to the existing http.Server so no new port is needed.
 */
export function installWsRelayHandler(
  server: http.Server,
  authToken: string,
  transform: FrameTransformer,
  getAllowedDomains: () => string[],
): void {
  // WebSocketServer in "noServer" mode — we handle the upgrade manually so we
  // can authenticate and validate before handing off to wss.
  const wss = new WebSocketServer({ noServer: true });

  // Handle WebSocket upgrades on the existing HTTP server
  server.on("upgrade", (req, socket, head) => {
    // Only handle our relay path
    const urlPath = req.url?.split("?")[0] ?? "/";
    if (urlPath !== "/ws-relay") {
      socket.destroy();
      return;
    }

    // Authenticate the client
    const rawToken = req.headers["x-proxy-token"];
    const clientToken = Array.isArray(rawToken) ? rawToken[0] : (rawToken ?? "");
    if (clientToken !== authToken) {
      logger.warn(
        `ws-relay: rejected unauthenticated upgrade from ${(socket as NodeJS.Socket & { remoteAddress?: string }).remoteAddress}`,
      );
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    // Extract and validate the target URL
    const rawTargetUrl = req.headers["x-ws-target-url"];
    const targetUrlStr = Array.isArray(rawTargetUrl) ? rawTargetUrl[0] : (rawTargetUrl ?? "");
    if (!targetUrlStr) {
      logger.warn("ws-relay: missing X-WS-Target-URL header");
      socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      socket.destroy();
      return;
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(targetUrlStr);
    } catch {
      logger.warn(`ws-relay: invalid X-WS-Target-URL: ${targetUrlStr}`);
      socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      socket.destroy();
      return;
    }

    // Allowlist check
    const allowedDomains = getAllowedDomains();
    if (!isDomainAllowed(targetUrl.toString(), allowedDomains)) {
      logger.warn(`ws-relay: blocked connection to non-allowlisted host: ${targetUrl.hostname}`);
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    logger.info(`ws-relay: opening relay to ${targetUrl.hostname}`);

    // Accept the upgrade
    wss.handleUpgrade(req, socket, head, (containerWs) => {
      void startRelay(containerWs, targetUrl.toString(), transform).catch((err) => {
        logger.error(`ws-relay: relay error for ${targetUrl.hostname}: ${String(err)}`);
        if (containerWs.readyState === WebSocket.OPEN) {
          containerWs.close(1011, "Relay error");
        }
      });
    });
  });

  logger.debug("ws-relay: relay handler installed on /ws-relay");
}

/**
 * Bridge a container WebSocket to a real upstream WSS target.
 */
async function startRelay(
  containerWs: WebSocket,
  targetUrl: string,
  transform: FrameTransformer,
): Promise<void> {
  return new Promise<void>((resolve) => {
    // Open upstream connection (WSS to Discord/etc.)
    const upstream = new WebSocket(targetUrl);

    let closed = false;
    const cleanup = (reason: string) => {
      if (closed) {
        return;
      }
      closed = true;
      logger.debug(`ws-relay: closing relay (${reason})`);
      if (upstream.readyState === WebSocket.OPEN || upstream.readyState === WebSocket.CONNECTING) {
        upstream.close();
      }
      if (containerWs.readyState === WebSocket.OPEN) {
        containerWs.close();
      }
      resolve();
    };

    upstream.on("open", () => {
      logger.info(`ws-relay: upstream connected to ${targetUrl}`);
    });

    // Container → Discord: inspect text frames for placeholders.
    // The ws library delivers data as Buffer (or Buffer[]) — never raw strings —
    // so we always convert non-binary frames via Buffer.toString().
    containerWs.on("message", (data, isBinary) => {
      if (upstream.readyState !== WebSocket.OPEN) {
        return;
      }

      if (isBinary) {
        // Binary frame: pass through unchanged
        upstream.send(data, { binary: true });
        return;
      }

      // Text frame — convert to string and check for placeholders.
      // The ws library delivers data as Buffer, Buffer[], or ArrayBuffer.
      let text: string;
      if (Buffer.isBuffer(data)) {
        text = data.toString("utf8");
      } else if (Array.isArray(data)) {
        text = Buffer.concat(data).toString("utf8");
      } else {
        text = Buffer.from(data).toString("utf8");
      }
      if (text.length <= MAX_INSPECT_SIZE && text.includes("{{")) {
        void transform(text)
          .then((transformed) => {
            if (transformed !== text) {
              logger.debug(`ws-relay: replaced placeholder in text frame`);
            }
            if (upstream.readyState === WebSocket.OPEN) {
              upstream.send(transformed);
            }
          })
          .catch((err) => {
            logger.warn(`ws-relay: transform error: ${String(err)}`);
            if (upstream.readyState === WebSocket.OPEN) {
              upstream.send(text); // forward original on transform failure
            }
          });
      } else {
        upstream.send(text);
      }
    });

    // Discord → Container: forward as-is
    upstream.on("message", (data, isBinary) => {
      if (containerWs.readyState === WebSocket.OPEN) {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
        containerWs.send(buf, { binary: isBinary });
      }
    });

    // Close propagation — guard against reserved codes (1005/1006) that
    // the ws library may emit but are invalid in a .close() call.
    const safeCloseCode = (code: number): number =>
      (code >= 1000 && code <= 1003) || (code >= 3000 && code <= 4999) ? code : 1000;

    containerWs.on("close", (code, reason) => {
      if (upstream.readyState === WebSocket.OPEN) {
        upstream.close(safeCloseCode(code), reason);
      }
      cleanup("container closed");
    });

    upstream.on("close", (code, reason) => {
      if (containerWs.readyState === WebSocket.OPEN) {
        containerWs.close(safeCloseCode(code), reason);
      }
      cleanup("upstream closed");
    });

    // Error handling
    containerWs.on("error", (err) => {
      logger.warn(`ws-relay: container WS error: ${String(err)}`);
      cleanup("container error");
    });

    upstream.on("error", (err) => {
      logger.warn(`ws-relay: upstream WS error: ${String(err)}`);
      cleanup("upstream error");
    });
  });
}
