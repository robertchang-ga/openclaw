import { GatewayIntents, GatewayPlugin } from "@buape/carbon/gateway";
import type { APIGatewayBotInfo } from "discord-api-types/v10";
import { HttpsProxyAgent } from "https-proxy-agent";
import { ProxyAgent, fetch as undiciFetch } from "undici";
import WebSocket from "ws";
import type { DiscordAccountConfig } from "../../config/types.js";
import { danger } from "../../globals.js";
import type { RuntimeEnv } from "../../runtime.js";

export function resolveDiscordGatewayIntents(
  intentsConfig?: import("../../config/types.discord.js").DiscordIntentsConfig,
): number {
  let intents =
    GatewayIntents.Guilds |
    GatewayIntents.GuildMessages |
    GatewayIntents.MessageContent |
    GatewayIntents.DirectMessages |
    GatewayIntents.GuildMessageReactions |
    GatewayIntents.DirectMessageReactions |
    GatewayIntents.GuildVoiceStates;
  if (intentsConfig?.presence) {
    intents |= GatewayIntents.GuildPresences;
  }
  if (intentsConfig?.guildMembers) {
    intents |= GatewayIntents.GuildMembers;
  }
  return intents;
}

/** ws-relay+ scheme prefix used by sanitize-secrets.ts in secure mode. */
const WS_RELAY_PREFIX = "ws-relay+";

export function createDiscordGatewayPlugin(params: {
  discordConfig: DiscordAccountConfig;
  runtime: RuntimeEnv;
}): GatewayPlugin {
  const intents = resolveDiscordGatewayIntents(params.discordConfig?.intents);
  const proxy = params.discordConfig?.proxy?.trim();
  const options = {
    reconnect: { maxAttempts: 50 },
    intents,
    autoInteractions: true,
  };

  if (!proxy) {
    return new GatewayPlugin(options);
  }

  const isWsRelay = proxy.startsWith(WS_RELAY_PREFIX);

  try {
    // In secure mode, sanitize-secrets.ts sets the proxy to ws-relay+http://host:port.
    // This signals that the proxy provides a WebSocket relay endpoint at /ws-relay
    // which handles TLS termination and secret injection for the Discord gateway.
    const resolvedProxy = isWsRelay ? proxy.slice(WS_RELAY_PREFIX.length) : proxy;
    // REST API: in ws-relay mode, the relay doesn't support HTTP CONNECT so
    // ProxyAgent would hang. Use default fetch (container has bridge network).
    // In standard proxy mode, use ProxyAgent for the gateway bot info request.
    const fetchAgent = isWsRelay ? null : new ProxyAgent(resolvedProxy);
    // Gateway WebSocket: use ws-relay endpoint or standard CONNECT tunnel.
    const wsAgent = isWsRelay ? null : new HttpsProxyAgent<string>(resolvedProxy);
    // The proxy auth token for the ws-relay endpoint.
    const proxyAuthToken = process.env.PROXY_AUTH_TOKEN?.trim();

    params.runtime.log?.(
      isWsRelay ? "discord: gateway ws-relay proxy enabled" : "discord: gateway proxy enabled",
    );

    class ProxyGatewayPlugin extends GatewayPlugin {
      constructor() {
        super(options);
      }

      override async registerClient(client: Parameters<GatewayPlugin["registerClient"]>[0]) {
        if (!this.gatewayInfo) {
          try {
            // In ws-relay mode (fetchAgent = null) the gateway container has no bridge network
            // access; use globalThis.fetch (= secureFetch inside the container) so the request
            // routes through the relay proxy and the Discord token placeholder is replaced.
            // In standard CONNECT-proxy mode use undiciFetch + ProxyAgent dispatcher as before.
            const response = fetchAgent
              ? await undiciFetch("https://discord.com/api/v10/gateway/bot", {
                  headers: {
                    Authorization: `Bot ${client.options.token}`,
                  },
                  dispatcher: fetchAgent,
                } as Record<string, unknown>)
              : await fetch("https://discord.com/api/v10/gateway/bot", {
                  headers: {
                    Authorization: `Bot ${client.options.token}`,
                  },
                });
            this.gatewayInfo = (await response.json()) as APIGatewayBotInfo;
          } catch (error) {
            throw new Error(
              `Failed to get gateway information from Discord: ${error instanceof Error ? error.message : String(error)}`,
              { cause: error },
            );
          }
        }
        return super.registerClient(client);
      }

      override createWebSocket(url: string) {
        if (wsAgent) {
          // Standard CONNECT tunnel proxy
          return new WebSocket(url, { agent: wsAgent });
        }
        // WS relay mode: connect to the relay endpoint and pass the target URL
        // as a header. The relay opens the real WSS connection to Discord and
        // relays frames, injecting secrets into text frames with placeholders.
        const relayUrl = resolvedProxy.replace(/^https?:/, "ws:") + "/ws-relay";
        return new WebSocket(relayUrl, {
          headers: {
            "X-WS-Target-URL": url,
            ...(proxyAuthToken ? { "X-Proxy-Token": proxyAuthToken } : {}),
          },
        });
      }
    }

    return new ProxyGatewayPlugin();
  } catch (err) {
    params.runtime.error?.(danger(`discord: invalid gateway proxy: ${String(err)}`));
    return new GatewayPlugin(options);
  }
}
