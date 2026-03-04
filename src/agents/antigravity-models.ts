/**
 * Dynamic discovery of google-antigravity models from the live API.
 *
 * Calls the same `fetchAvailableModels` endpoint used by provider-usage
 * to discover model IDs, then synthesises model definitions for any IDs
 * not already present in the SDK's built-in catalog.  The discovered
 * models are merged by `ensureOpenClawModelsJson`'s existing logic, so
 * they appear alongside hardcoded entries without replacing them.
 */
import { loadConfig } from "../config/config.js";
import type { ModelDefinitionConfig } from "../config/types.models.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import {
  ensureAuthProfileStore,
  listProfilesForProvider,
  resolveApiKeyForProfile,
  resolveAuthProfileOrder,
} from "./auth-profiles.js";
import { dedupeProfileIds } from "./auth-profiles/profiles.js";

const log = createSubsystemLogger("agents/antigravity-models");

const BASE_URL = "https://cloudcode-pa.googleapis.com";
const FETCH_AVAILABLE_MODELS_PATH = "/v1internal:fetchAvailableModels";
const DISCOVERY_TIMEOUT_MS = 5_000;

// Internal model prefixes to skip — these are autocomplete/tab models, not chat.
const INTERNAL_PREFIXES = ["chat_", "tab_", "code_"];

// Template model definition for synthesising discovered models.
// Uses the same shape as existing Antigravity models in the SDK catalog.
const DEFAULT_CONTEXT_WINDOW = 200_000;
const DEFAULT_MAX_TOKENS = 65_536;
const DEFAULT_COST = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };

type FetchAvailableModelsResponse = {
  models?: Record<
    string,
    {
      displayName?: string;
    }
  >;
};

/** Extract the raw OAuth bearer token from a Google-format API key. */
function parseGoogleToken(apiKey: string): string {
  try {
    const parsed = JSON.parse(apiKey) as { token?: unknown };
    if (parsed && typeof parsed.token === "string") {
      return parsed.token;
    }
  } catch {
    // not JSON-wrapped, use as-is
  }
  return apiKey;
}

/**
 * Resolve an OAuth token for the google-antigravity provider.
 * Mirrors the logic in provider-usage.auth.ts but kept self-contained
 * so the discovery module has no circular dependency on the usage layer.
 */
async function resolveAntigravityToken(agentDir?: string): Promise<string | null> {
  const cfg = loadConfig();
  const store = ensureAuthProfileStore(agentDir, {
    allowKeychainPrompt: false,
  });
  const order = resolveAuthProfileOrder({
    cfg,
    store,
    provider: "google-antigravity",
  });
  const deduped = dedupeProfileIds(order);

  for (const profileId of deduped) {
    const cred = store.profiles[profileId];
    if (!cred || (cred.type !== "oauth" && cred.type !== "token")) {
      continue;
    }
    try {
      const resolved = await resolveApiKeyForProfile({
        cfg: undefined,
        store,
        profileId,
        agentDir,
      });
      if (resolved) {
        return parseGoogleToken(resolved.apiKey);
      }
    } catch {
      // ignore
    }
  }
  return null;
}

function isInternalModel(modelId: string): boolean {
  const lower = modelId.toLowerCase();
  return INTERNAL_PREFIXES.some((prefix) => lower.includes(prefix));
}

function inferReasoning(modelId: string): boolean {
  const lower = modelId.toLowerCase();
  return lower.includes("thinking") || lower.includes("reasoning");
}

function inferInput(modelId: string): Array<"text" | "image"> {
  // Models with "flash" or "vision" typically support image input.
  // Conservative default: text-only unless the name suggests vision.
  const lower = modelId.toLowerCase();
  if (
    lower.includes("flash") ||
    lower.includes("pro") ||
    lower.includes("vision") ||
    lower.includes("gemini")
  ) {
    return ["text", "image"];
  }
  return ["text"];
}

function buildModelDefinition(modelId: string): ModelDefinitionConfig {
  return {
    id: modelId,
    name: modelId,
    reasoning: inferReasoning(modelId),
    input: inferInput(modelId),
    cost: DEFAULT_COST,
    contextWindow: DEFAULT_CONTEXT_WINDOW,
    maxTokens: DEFAULT_MAX_TOKENS,
  };
}

const TOKEN_TIMEOUT_MS = 5_000;

/**
 * Race a promise against a timeout; resolves to `null` if the timeout fires first.
 */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([
    promise,
    new Promise<null>((resolve) => setTimeout(() => resolve(null), ms)),
  ]);
}

/**
 * Discover Antigravity models from the live API.
 *
 * Returns an array of `ModelDefinitionConfig` for models that the
 * current user has access to.  On any error (network, auth, timeout)
 * returns an empty array — callers should treat this as a best-effort
 * supplement to the static catalog.
 */
export async function discoverAntigravityModels(params?: {
  agentDir?: string;
}): Promise<ModelDefinitionConfig[]> {
  try {
    const token = await withTimeout(resolveAntigravityToken(params?.agentDir), TOKEN_TIMEOUT_MS);
    if (!token) {
      log.debug("No OAuth token available for google-antigravity; skipping discovery.");
      return [];
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DISCOVERY_TIMEOUT_MS);
    try {
      const res = await fetch(`${BASE_URL}${FETCH_AVAILABLE_MODELS_PATH}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "User-Agent": "antigravity",
          "X-Goog-Api-Client": "google-cloud-sdk vscode_cloudshelleditor/0.1",
        },
        body: JSON.stringify({}),
        signal: controller.signal,
      });

      if (!res.ok) {
        log.debug(`fetchAvailableModels returned ${res.status}; skipping discovery.`);
        return [];
      }

      const data = (await res.json()) as FetchAvailableModelsResponse;
      if (!data.models || typeof data.models !== "object") {
        return [];
      }

      const models: ModelDefinitionConfig[] = [];
      for (const modelId of Object.keys(data.models)) {
        if (isInternalModel(modelId)) {
          continue;
        }
        models.push(buildModelDefinition(modelId));
      }

      log.debug(`Discovered ${models.length} Antigravity models from API.`);
      return models;
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    log.debug(`Antigravity model discovery failed: ${String(err)}`);
    return [];
  }
}

/**
 * Check whether the google-antigravity provider has any configured profiles.
 */
export function hasAntigravityProfiles(agentDir?: string): boolean {
  const store = ensureAuthProfileStore(agentDir, {
    allowKeychainPrompt: false,
  });
  return listProfilesForProvider(store, "google-antigravity").length > 0;
}
