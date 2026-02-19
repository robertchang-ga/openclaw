
import { resolveBrowserConfig } from "../browser/config.js";
import { loadConfig } from "../config/config.js";
import { GatewayClient } from "../gateway/client.js";
import { getMachineDisplayName } from "../infra/machine-name.js";
import { ensureOpenClawCliOnPath } from "../infra/path-env.js";
import { GATEWAY_CLIENT_MODES, GATEWAY_CLIENT_NAMES } from "../utils/message-channel.js";
import { VERSION } from "../version.js";
import { ensureNodeHostConfig, saveNodeHostConfig, type NodeHostGatewayConfig } from "./config.js";
import {
  coerceNodeInvokePayload,
  handleInvoke,
  type SkillBinsProvider,
  buildNodeInvokeResultParams,
} from "./invoke.js";

export { buildNodeInvokeResultParams };

type NodeHostRunOptions = {
  gatewayHost: string;
  gatewayPort: number;
  gatewayTls?: boolean;
  gatewayTlsFingerprint?: string;
  nodeId?: string;
  displayName?: string;
  /** Explicit gateway auth token (preferred over env var). */
  token?: string;
  /** Explicit gateway auth password (preferred over env var). */
  password?: string;
  /**
   * When true, skip all filesystem persistence (config, device identity).
   * Used when embedding the node host in the --secure mode process.
   */
  embedded?: boolean;
};

const DEFAULT_NODE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

class SkillBinsCache implements SkillBinsProvider {
  private bins = new Set<string>();
  private lastRefresh = 0;
  private readonly ttlMs = 90_000;
  private readonly fetch: () => Promise<string[]>;

  constructor(fetch: () => Promise<string[]>) {
    this.fetch = fetch;
  }

  async current(force = false): Promise<Set<string>> {
    if (force || Date.now() - this.lastRefresh > this.ttlMs) {
      await this.refresh();
    }
    return this.bins;
  }

  private async refresh() {
    try {
      const bins = await this.fetch();
      this.bins = new Set(bins);
      this.lastRefresh = Date.now();
    } catch {
      if (!this.lastRefresh) {
        this.bins = new Set();
      }
    }
  }
}

function ensureNodePathEnv(): string {
  ensureOpenClawCliOnPath({ pathEnv: process.env.PATH ?? "" });
  const current = process.env.PATH ?? "";
  if (current.trim()) {
    return current;
  }
  process.env.PATH = DEFAULT_NODE_PATH;
  return DEFAULT_NODE_PATH;
}

/**
 * Start the node host and return the GatewayClient (non-blocking).
 * Use this when embedding the node host in another process (e.g. --secure mode).
 */
export async function startNodeHost(opts: NodeHostRunOptions): Promise<GatewayClient> {
  let nodeId: string;
  let displayName: string;
  let tls: boolean;
  let token: string | undefined;
  let password: string | undefined;
  let browserProxyEnabled: boolean;
  let skipDeviceAuth: boolean;

  if (opts.embedded) {
    // Embedded mode: skip all filesystem persistence and device auth.
    // Use caller-provided values and authenticate via shared secret only.
    nodeId = opts.nodeId?.trim() || `embedded-${Date.now()}`;
    displayName = opts.displayName?.trim() || "Embedded Node Host";
    tls = opts.gatewayTls ?? false;
    token = opts.token?.trim() || process.env.OPENCLAW_GATEWAY_TOKEN?.trim() || undefined;
    password = opts.password?.trim() || process.env.OPENCLAW_GATEWAY_PASSWORD?.trim() || undefined;
    browserProxyEnabled = false;
    skipDeviceAuth = true;
  } else {
    const config = await ensureNodeHostConfig();
    nodeId = opts.nodeId?.trim() || config.nodeId;
    if (nodeId !== config.nodeId) {
      config.nodeId = nodeId;
    }
    displayName =
      opts.displayName?.trim() || config.displayName || (await getMachineDisplayName());
    config.displayName = displayName;

    const gateway: NodeHostGatewayConfig = {
      host: opts.gatewayHost,
      port: opts.gatewayPort,
      tls: opts.gatewayTls ?? loadConfig().gateway?.tls?.enabled ?? false,
      tlsFingerprint: opts.gatewayTlsFingerprint,
    };
    config.gateway = gateway;
    await saveNodeHostConfig(config);

    const cfg = loadConfig();
    const resolvedBrowser = resolveBrowserConfig(cfg.browser, cfg);
    browserProxyEnabled =
      cfg.nodeHost?.browserProxy?.enabled !== false && resolvedBrowser.enabled;
    const isRemoteMode = cfg.gateway?.mode === "remote";
    tls = gateway.tls ?? false;
    token =
      process.env.OPENCLAW_GATEWAY_TOKEN?.trim() ||
      (isRemoteMode ? cfg.gateway?.remote?.token : cfg.gateway?.auth?.token);
    password =
      process.env.OPENCLAW_GATEWAY_PASSWORD?.trim() ||
      (isRemoteMode ? cfg.gateway?.remote?.password : cfg.gateway?.auth?.password);
    skipDeviceAuth = false;
  }

  const host = opts.gatewayHost ?? "127.0.0.1";
  const port = opts.gatewayPort ?? 18789;
  const scheme = tls ? "wss" : "ws";
  const url = `${scheme}://${host}:${port}`;
  const pathEnv = ensureNodePathEnv();
  // eslint-disable-next-line no-console
  console.log(`node host PATH: ${pathEnv}`);

  const client = new GatewayClient({
    url,
    token: token?.trim() || undefined,
    password: password?.trim() || undefined,
    instanceId: nodeId,
    clientName: GATEWAY_CLIENT_NAMES.NODE_HOST,
    clientDisplayName: displayName,
    clientVersion: VERSION,
    platform: process.platform,
    mode: GATEWAY_CLIENT_MODES.NODE,
    role: "node",
    scopes: [],
    caps: ["system", ...(browserProxyEnabled ? ["browser"] : [])],
    commands: [
      "system.run",
      "system.which",
      "system.execApprovals.get",
      "system.execApprovals.set",
      ...(browserProxyEnabled ? ["browser.proxy"] : []),
    ],
    pathEnv,
    permissions: undefined,
    skipDeviceAuth,
    tlsFingerprint: opts.gatewayTlsFingerprint,
    onEvent: (evt) => {
      if (evt.event !== "node.invoke.request") {
        return;
      }
      const payload = coerceNodeInvokePayload(evt.payload);
      if (!payload) {
        return;
      }
      void handleInvoke(payload, client, skillBins);
    },
    onConnectError: (err) => {
      // keep retrying (handled by GatewayClient)
      // eslint-disable-next-line no-console
      console.error(`node host gateway connect failed: ${err.message}`);
    },
    onClose: (code, reason) => {
      // eslint-disable-next-line no-console
      console.error(`node host gateway closed (${code}): ${reason}`);
    },
  });

  const skillBins = new SkillBinsCache(async () => {
    const res = await client.request<{ bins: Array<unknown> }>("skills.bins", {});
    const bins = Array.isArray(res?.bins) ? res.bins.map((bin) => String(bin)) : [];
    return bins;
  });

  client.start();
  return client;
}

/**
 * Run the node host standalone (blocks forever).
 * Used by the `openclaw node-host` CLI command.
 */
export async function runNodeHost(opts: NodeHostRunOptions): Promise<void> {
  await startNodeHost(opts);
  await new Promise(() => {});
}
