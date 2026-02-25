import { RELAY_CONTAINER_NAME } from "../security/gateway-container.js";
import type { OpenClawConfig } from "./types.openclaw.js";

/**
 * Sanitizes a config object by replacing sensitive values with placeholders.
 * Used in secure mode to ensure no secrets exist in the container.
 * @param opts.force - If true, sanitize regardless of OPENCLAW_SECURE_MODE env var
 * @param opts.proxyPort - Proxy port for setting discord.proxy WS relay URL (secure mode only)
 */
export function sanitizeConfigSecrets(
  cfg: OpenClawConfig,
  opts?: { force?: boolean; proxyPort?: number },
): OpenClawConfig {
  // Only sanitize when explicitly requested by the caller.
  if (!opts?.force) {
    return cfg;
  }

  // Deep clone to avoid mutating the original
  const sanitized = JSON.parse(JSON.stringify(cfg)) as OpenClawConfig;

  // Sanitize channel secrets
  if (sanitized.channels) {
    // Discord
    if (sanitized.channels.discord?.token) {
      sanitized.channels.discord.token = "{{CONFIG:channels.discord.token}}";
      // Route the Discord gateway WebSocket through the secrets proxy for token injection.
      // The proxy's WS relay endpoint (at /ws-relay) intercepts the IDENTIFY frame and
      // replaces the placeholder with the real token before forwarding to Discord.
      // proxyPort is only passed in secure mode (force=true), so this guard is
      // intentionally separate from the force check above.
      if (opts?.proxyPort) {
        sanitized.channels.discord.proxy = `ws-relay+http://${RELAY_CONTAINER_NAME}:${opts.proxyPort}`;
      }
    }

    // Telegram
    if (sanitized.channels.telegram) {
      if (sanitized.channels.telegram.botToken) {
        sanitized.channels.telegram.botToken = "{{CONFIG:channels.telegram.botToken}}";
      }
      if (sanitized.channels.telegram.webhookSecret) {
        sanitized.channels.telegram.webhookSecret = "{{CONFIG:channels.telegram.webhookSecret}}";
      }
    }

    // Slack
    if (sanitized.channels.slack) {
      if (sanitized.channels.slack.botToken) {
        sanitized.channels.slack.botToken = "{{CONFIG:channels.slack.botToken}}";
      }
      if (sanitized.channels.slack.appToken) {
        sanitized.channels.slack.appToken = "{{CONFIG:channels.slack.appToken}}";
      }
      if (sanitized.channels.slack.userToken) {
        sanitized.channels.slack.userToken = "{{CONFIG:channels.slack.userToken}}";
      }
      if (sanitized.channels.slack.signingSecret) {
        sanitized.channels.slack.signingSecret = "{{CONFIG:channels.slack.signingSecret}}";
      }
    }

    // Feishu
    const feishu = sanitized.channels.feishu;
    if (feishu) {
      if (feishu.appId) {
        feishu.appId = "{{CONFIG:channels.feishu.appId}}";
      }
      if (feishu.appSecret) {
        feishu.appSecret = "{{CONFIG:channels.feishu.appSecret}}";
      }
    }

    // Google Chat
    if (sanitized.channels.googlechat?.serviceAccount) {
      sanitized.channels.googlechat.serviceAccount =
        "{{CONFIG:channels.googlechat.serviceAccount}}";
    }
  }

  // Sanitize gateway remote credentials (for connecting TO a remote gateway)
  if (sanitized.gateway?.remote) {
    if (sanitized.gateway.remote.token) {
      sanitized.gateway.remote.token = "{{CONFIG:gateway.remote.token}}";
    }
    if (sanitized.gateway.remote.password) {
      sanitized.gateway.remote.password = "{{CONFIG:gateway.remote.password}}";
    }
  }

  // Sanitize gateway auth credentials (for inbound authentication)
  // The container uses OPENCLAW_GATEWAY_TOKEN env var injected at runtime instead.
  // We must DELETE these keys (not replace with placeholders) because
  // resolveGatewayAuth uses `authConfig.token ?? env.OPENCLAW_GATEWAY_TOKEN`
  // and a placeholder string is truthy, preventing the env var fallback.
  if (sanitized.gateway?.auth) {
    if (sanitized.gateway.auth.token) {
      delete sanitized.gateway.auth.token;
    }
    if (sanitized.gateway.auth.password) {
      delete sanitized.gateway.auth.password;
    }
  }

  // Sanitize talk API key (ElevenLabs)
  if (sanitized.talk?.apiKey) {
    sanitized.talk.apiKey = "{{CONFIG:talk.apiKey}}";
  }

  // Sanitize inline env vars
  if (sanitized.env?.vars) {
    for (const key of Object.keys(sanitized.env.vars)) {
      // Only sanitize keys that look like secrets (case-insensitive)
      const upperKey = key.toUpperCase();
      if (
        upperKey.includes("KEY") ||
        upperKey.includes("SECRET") ||
        upperKey.includes("TOKEN") ||
        upperKey.includes("PASSWORD")
      ) {
        sanitized.env.vars[key] = `{{CONFIG:env.vars.${key}}}`;
      }
    }
  }

  // Sanitize tool API keys
  if (sanitized.tools?.web?.search?.apiKey) {
    sanitized.tools.web.search.apiKey = "{{CONFIG:tools.web.search.apiKey}}";
  }
  if (sanitized.tools?.web?.search?.perplexity?.apiKey) {
    sanitized.tools.web.search.perplexity.apiKey = "{{CONFIG:tools.web.search.perplexity.apiKey}}";
  }
  if (sanitized.tools?.web?.fetch?.firecrawl?.apiKey) {
    sanitized.tools.web.fetch.firecrawl.apiKey = "{{CONFIG:tools.web.fetch.firecrawl.apiKey}}";
  }
  const toolsUnknown = (sanitized as Record<string, unknown>).tools as
    | Record<string, unknown>
    | undefined;
  const memoryTool = toolsUnknown?.memory as Record<string, unknown> | undefined;
  const remoteMemory = memoryTool?.remote as Record<string, unknown> | undefined;
  if (remoteMemory?.apiKey) {
    remoteMemory.apiKey = "{{CONFIG:tools.memory.remote.apiKey}}";
  }

  // Sanitize agent workspace paths (rewrite host home dir to container path)
  if (sanitized.agents) {
    // Handle agents.defaults.workspace
    const defaults = (sanitized.agents as Record<string, unknown>).defaults as
      | Record<string, unknown>
      | undefined;
    if (defaults?.workspace && typeof defaults.workspace === "string") {
      defaults.workspace = defaults.workspace.replace(/^\/home\/[^/]+\//, "/home/node/");
    }

    // Handle per-agent workspaces (agents[agentId].workspace)
    const agents = sanitized.agents as Record<string, { workspace?: string } | undefined>;
    for (const agentId of Object.keys(agents)) {
      if (agentId === "defaults") {
        continue; // Already handled above
      }
      const agent = agents[agentId];
      if (agent?.workspace && typeof agent.workspace === "string") {
        // Replace any home directory path with container path
        // This handles paths like /home/username/.openclaw/workspace
        agent.workspace = agent.workspace.replace(/^\/home\/[^/]+\//, "/home/node/");
      }
    }
  }

  // Rewrite localhost URLs in plugin configs to Docker-internal hostnames.
  // In secure mode, localhost inside the container refers to the container
  // itself, not the host. Sidecar services (cognee, speaches) are on
  // openclaw-secure-net and reachable by container name.
  const SIDECAR_PORT_MAP: Record<string, { hostname: string; containerPort: string }> = {
    "8000": { hostname: "cognee", containerPort: "8000" },
    "8090": { hostname: "speaches", containerPort: "8000" },
  };
  if (sanitized.plugins?.entries) {
    for (const entry of Object.values(sanitized.plugins.entries)) {
      const rec = entry as Record<string, unknown> | undefined;
      if (rec?.baseUrl && typeof rec.baseUrl === "string") {
        try {
          const parsed = new URL(rec.baseUrl);
          if (
            (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") &&
            SIDECAR_PORT_MAP[parsed.port]
          ) {
            const mapping = SIDECAR_PORT_MAP[parsed.port];
            parsed.hostname = mapping.hostname;
            parsed.port = mapping.containerPort;
            rec.baseUrl = parsed.toString().replace(/\/$/, "");
          }
        } catch {
          /* invalid URL, leave unchanged */
        }
      }
    }
  }

  return sanitized;
}
