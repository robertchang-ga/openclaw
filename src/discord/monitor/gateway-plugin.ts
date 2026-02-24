import { GatewayIntents, GatewayPlugin } from "@buape/carbon/gateway";
import { HttpsProxyAgent } from "https-proxy-agent";
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

  try {
    // Detect secure-mode WS relay proxy (set automatically by sanitize-secrets.ts).
    // The proxy URL uses the "ws-relay+" scheme prefix followed by the relay base URL.
    // e.g. "ws-relay+http://openclaw-relay:8012"
    // In this mode we connect plain WS to {relayBase}/ws-relay and let the proxy
    // establish the real WSS connection to Discord. This avoids TLS interception
    // on the container side (no self-signed cert needed).
    if (proxy.startsWith("ws-relay+")) {
      const relayBase = proxy.slice("ws-relay+".length);
      const proxyAuthToken = process.env.PROXY_AUTH_TOKEN ?? "";
      if (!proxyAuthToken) {
        params.runtime.error?.(
          "discord: PROXY_AUTH_TOKEN is not set — WS relay requests will fail auth",
        );
      }

      params.runtime.log?.("discord: using secure WS relay for gateway");

      class WsRelayGatewayPlugin extends GatewayPlugin {
        constructor() {
          super(options);
        }

        createWebSocket(targetUrl: string) {
          // Convert relay base URL to WS scheme (http→ws, https→wss)
          const relayWsBase = relayBase.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
          const relayEndpoint = `${relayWsBase}/ws-relay`;

          return new WebSocket(relayEndpoint, {
            headers: {
              "x-ws-target-url": targetUrl,
              "x-proxy-token": proxyAuthToken,
            },
          });
        }
      }

      return new WsRelayGatewayPlugin();
    }

    // Standard HTTPS proxy (existing behaviour for externally configured proxies)
    const agent = new HttpsProxyAgent<string>(proxy);

    params.runtime.log?.("discord: gateway proxy enabled");

    class ProxyGatewayPlugin extends GatewayPlugin {
      constructor() {
        super(options);
      }

      createWebSocket(url: string) {
        return new WebSocket(url, { agent });
      }
    }

    return new ProxyGatewayPlugin();
  } catch (err) {
    params.runtime.error?.(danger(`discord: invalid gateway proxy: ${String(err)}`));
    return new GatewayPlugin(options);
  }
}
