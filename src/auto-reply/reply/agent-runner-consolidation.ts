import crypto from "node:crypto";
import { runEmbeddedPiAgent } from "../../agents/pi-embedded.js";
import type { OpenClawConfig } from "../../config/config.js";
import type { SessionEntry } from "../../config/sessions.js";
import { logVerbose } from "../../globals.js";
import { registerAgentRunContext } from "../../infra/agent-events.js";

const CONSOLIDATION_TIMEOUT_MS = 120_000; // 2 minutes

/**
 * Build the consolidation prompt that instructs the agent to write
 * an episodic reflection and update MEMORY.md before the session is wiped.
 */
function buildConsolidationPrompt(): string {
  return [
    "MEMORY CONSOLIDATION — SLEEP CYCLE",
    "",
    "Your session is about to be reset. Before your memory is wiped, you must consolidate your memories from this session.",
    "",
    "Perform the following steps IMMEDIATELY:",
    "",
    "1. **Episodic Reflection** — Write a structured reflection file to `memory/episodes/` with this exact format:",
    "   - Filename: `YYYYMMDD_HHMMSS.md` (current timestamp)",
    "   - YAML frontmatter with: type: episode, session_id, date, time_range, tags, outcome (success/partial/failure), salience (high/medium/low), trigger",
    "   - Sections: What Happened, What Succeeded, What Failed, What's Pending, Key Decisions, Tools & Artifacts, Context & Connections",
    "   - Be specific about what you worked on, what you decided, and why",
    "   - Link to previous episodes or decisions if relevant",
    "",
    "2. **Semantic Memory Update** — Append to `MEMORY.md` any durable facts, preferences, entities, or decisions from this session that should persist across sessions. Use append-only — never delete existing content.",
    "",
    "3. If the `memory-consolidation` skill is available, follow its detailed instructions for format and entity normalization.",
    "",
    "Write these files now. This is your last chance before this session's context is lost forever.",
  ].join("\n");
}

/**
 * Run a consolidation agent turn before the session is reset.
 * The agent writes its episodic reflection and updates MEMORY.md.
 *
 * This follows the same pattern as `runMemoryFlushIfNeeded` but is called
 * from the reset command flow rather than the agent reply pipeline.
 */
export async function runConsolidationTurn(params: {
  cfg: OpenClawConfig;
  provider: string;
  model: string;
  sessionEntry?: SessionEntry;
  previousSessionEntry?: SessionEntry;
  sessionKey?: string;
  agentId?: string;
  agentDir?: string;
  workspaceDir: string;
}): Promise<void> {
  // Use the previous session entry (the one being reset), falling back to current
  const sessionEntry = params.previousSessionEntry ?? params.sessionEntry;
  const sessionFile = sessionEntry?.sessionFile;
  const sessionId = sessionEntry?.sessionId;

  if (!sessionFile || !sessionId) {
    logVerbose("consolidation turn: no session file or id available, skipping");
    return;
  }

  const runId = crypto.randomUUID();
  if (params.sessionKey) {
    registerAgentRunContext(runId, {
      sessionKey: params.sessionKey,
      verboseLevel: "off",
    });
  }

  logVerbose("consolidation turn: starting episodic reflection + MEMORY.md update");
  try {
    await runEmbeddedPiAgent({
      sessionId,
      sessionKey: params.sessionKey,
      agentId: params.agentId,
      sessionFile,
      workspaceDir: params.workspaceDir,
      agentDir: params.agentDir,
      config: params.cfg,
      prompt: buildConsolidationPrompt(),
      provider: params.provider,
      model: params.model,
      senderIsOwner: true,
      timeoutMs: CONSOLIDATION_TIMEOUT_MS,
      runId,
      // Suppress all output — this is a background consolidation turn
      suppressToolErrorWarnings: true,
    });
    logVerbose("consolidation turn: completed successfully");
  } catch (err) {
    logVerbose(`consolidation turn failed: ${String(err)}`);
  }
}
