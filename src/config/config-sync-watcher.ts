import fs from "node:fs";
import path from "node:path";
import { createConfigIO } from "./io.js";
import { sanitizeConfigSecrets } from "./sanitize-secrets.js";
import type { OpenClawConfig } from "./types.js";

/**
 * Placeholder pattern used by sanitizeConfigSecrets.
 * Matches {{CONFIG:path}}, {{OAUTH:id}}, {{APIKEY:id}}, {{TOKEN:id}}, etc.
 */
const PLACEHOLDER_RE = /^\{\{[A-Z_]+:[^}]+\}\}$/;

function isPlaceholder(value: unknown): boolean {
  return typeof value === "string" && PLACEHOLDER_RE.test(value);
}

/**
 * Compute the set of dotted config paths whose values differ between two configs.
 * Only walks into plain objects — arrays, primitives, and placeholders are compared as wholes.
 */
function diffPaths(
  baseline: Record<string, unknown>,
  updated: Record<string, unknown>,
  prefix: string,
  out: Map<string, unknown>,
): void {
  const allKeys = new Set([...Object.keys(baseline), ...Object.keys(updated)]);
  for (const key of allKeys) {
    const dotPath = prefix ? `${prefix}.${key}` : key;
    const bVal = baseline[key];
    const uVal = updated[key];

    // Skip if the updated value is still a placeholder — container didn't change this secret.
    if (isPlaceholder(uVal)) {
      continue;
    }

    // Key was deleted in updated config — record as explicit undefined.
    if (!(key in updated)) {
      // Don't propagate deletions of keys that were already deleted during sanitization
      // (e.g., gateway.auth.token is deleted by sanitizeConfigSecrets).
      if (key in baseline && isPlaceholder(bVal)) {
        continue;
      }
      out.set(dotPath, undefined);
      continue;
    }

    // Key was added in updated config.
    if (!(key in baseline)) {
      out.set(dotPath, uVal);
      continue;
    }

    // Both exist — recurse into sub-objects, or compare leaves.
    if (
      bVal &&
      uVal &&
      typeof bVal === "object" &&
      typeof uVal === "object" &&
      !Array.isArray(bVal) &&
      !Array.isArray(uVal)
    ) {
      diffPaths(bVal as Record<string, unknown>, uVal as Record<string, unknown>, dotPath, out);
    } else if (JSON.stringify(bVal) !== JSON.stringify(uVal)) {
      out.set(dotPath, uVal);
    }
  }
}

/**
 * Set a deeply nested value in an object by dotted path.
 * Intermediate objects are created as needed.
 */
function setDeep(obj: Record<string, unknown>, dotPath: string, value: unknown): void {
  const parts = dotPath.split(".");
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (!current[key] || typeof current[key] !== "object") {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }
  const lastKey = parts[parts.length - 1];
  if (value === undefined) {
    delete current[lastKey];
  } else {
    current[lastKey] = value;
  }
}

export type ConfigSyncTarget = {
  /** Path to the sanitized config file on the host (bind-mounted into the container). */
  sanitizedPath: string;
  /** Path to the real config file on the host (with actual secrets). */
  realPath: string;
};

export type ConfigSyncWatcher = {
  /** Stop watching and clean up. */
  stop: () => void;
};

/**
 * Watch the sanitized openclaw.json for changes written by the container's gateway,
 * and reverse-merge non-placeholder changes back to the real host config.
 *
 * Design:
 * 1. Capture a baseline snapshot of the sanitized config at start.
 * 2. On file change (debounced 300ms), re-read the sanitized file.
 * 3. Diff the new content against the baseline to find what the container actually changed.
 * 4. Skip any value that is still a placeholder (the container didn't change the secret).
 * 5. Apply the non-placeholder changes to the real config using createConfigIO().writeConfigFile.
 * 6. Re-sanitize and update the baseline snapshot.
 */
export function startConfigSyncWatcher(
  target: ConfigSyncTarget,
  logger: Pick<typeof console, "info" | "warn" | "error"> = console,
): ConfigSyncWatcher {
  const { sanitizedPath, realPath } = target;

  // Capture baseline: what the sanitized config looked like at mount time.
  let baselineContent: string | null = null;
  try {
    baselineContent = fs.readFileSync(sanitizedPath, "utf-8");
  } catch {
    logger.warn(`Config sync watcher: could not read baseline at ${sanitizedPath}`);
  }

  let debounceTimer: NodeJS.Timeout | null = null;
  let syncing = false;

  const syncBack = async () => {
    if (syncing) {
      return; // Skip re-entrant syncs.
    }
    syncing = true;
    try {
      const updatedContent = await fs.promises.readFile(sanitizedPath, "utf-8");

      // No change from baseline — nothing to sync.
      if (updatedContent === baselineContent) {
        return;
      }

      const updatedConfig = JSON.parse(updatedContent) as Record<string, unknown>;
      const baselineConfig = baselineContent
        ? (JSON.parse(baselineContent) as Record<string, unknown>)
        : {};

      // Compute what the container changed (excluding placeholder values).
      const changes = new Map<string, unknown>();
      diffPaths(baselineConfig, updatedConfig, "", changes);

      if (changes.size === 0) {
        // Only placeholder values differ — nothing to sync back.
        baselineContent = updatedContent;
        return;
      }

      // Apply changes to the real config.
      const realIO = createConfigIO({ configPath: realPath });
      const realConfig = realIO.loadConfig() as Record<string, unknown>;

      for (const [dotPath, value] of changes) {
        setDeep(realConfig, dotPath, value);
      }

      await realIO.writeConfigFile(realConfig as OpenClawConfig);

      // Re-sanitize the real config and update baseline so subsequent container
      // writes are diffed against the latest state.
      const freshReal = realIO.loadConfig();
      const freshSanitized = sanitizeConfigSecrets(freshReal, { force: true });
      const freshContent = JSON.stringify(freshSanitized, null, 2);

      // Write updated sanitized content back so the container sees a consistent snapshot.
      // Note: this write will trigger another fs.watch event, but the baselineContent
      // update below ensures the next syncBack is a no-op.
      await fs.promises.writeFile(sanitizedPath, freshContent, "utf-8");
      baselineContent = freshContent;

      const pathsList = [...changes.keys()].join(", ");
      logger.info(`Config sync: merged ${changes.size} change(s) to host config (${pathsList})`);
    } catch (err) {
      logger.error(`Config sync watcher error: ${String(err)}`);
    } finally {
      syncing = false;
    }
  };

  // Watch the sanitized file for changes.
  const watcher = fs.watch(path.dirname(sanitizedPath), (eventType, filename) => {
    if (filename && path.basename(sanitizedPath) === filename) {
      // Debounce: writeConfigFile writes atomically (tmp → rename/copy), so we may
      // get multiple events per write. Wait 300ms for things to settle.
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(() => {
        void syncBack();
      }, 300);
    }
  });

  return {
    stop: () => {
      watcher.close();
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
    },
  };
}
