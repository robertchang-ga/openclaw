import { ProxyAgent, fetch as undiciFetch } from "undici";
import { danger } from "../../globals.js";
import { wrapFetchWithAbortSignal } from "../../infra/fetch.js";
import type { RuntimeEnv } from "../../runtime.js";

/** ws-relay+ scheme prefix used by sanitize-secrets.ts in secure mode. */
const WS_RELAY_PREFIX = "ws-relay+";

export function resolveDiscordRestFetch(
  proxyUrl: string | undefined,
  runtime: RuntimeEnv,
): typeof fetch {
  const proxy = proxyUrl?.trim();
  if (!proxy) {
    return fetch;
  }
  // In secure mode, sanitize-secrets.ts sets the proxy to ws-relay+http://...
  // The relay container is a WebSocket relay, NOT an HTTP CONNECT proxy.
  // REST requests must use globalThis.fetch (= secureFetch inside the container,
  // which routes through the relay proxy) — ProxyAgent would hang because the
  // relay doesn't support CONNECT. The ws-relay endpoint is only for the
  // Discord gateway WebSocket.
  if (proxy.startsWith(WS_RELAY_PREFIX)) {
    runtime.log?.("discord: rest proxy skipped (ws-relay mode, using direct fetch)");
    return fetch;
  }
  try {
    const agent = new ProxyAgent(proxy);
    const fetcher = ((input: RequestInfo | URL, init?: RequestInit) =>
      undiciFetch(input as string | URL, {
        ...(init as Record<string, unknown>),
        dispatcher: agent,
      }) as unknown as Promise<Response>) as typeof fetch;
    runtime.log?.("discord: rest proxy enabled");
    return wrapFetchWithAbortSignal(fetcher);
  } catch (err) {
    runtime.error?.(danger(`discord: invalid rest proxy: ${String(err)}`));
    return fetch;
  }
}
