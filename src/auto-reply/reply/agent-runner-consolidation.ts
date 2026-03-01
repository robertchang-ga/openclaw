import crypto from "node:crypto";
import { runEmbeddedPiAgent } from "../../agents/pi-embedded.js";
import type { OpenClawConfig } from "../../config/config.js";
import type { SessionEntry } from "../../config/sessions.js";
import { logVerbose } from "../../globals.js";
import { registerAgentRunContext } from "../../infra/agent-events.js";

const CONSOLIDATION_TIMEOUT_MS = 180_000; // 3 minutes (covers pass 2 + episodic + fireflies)

/**
 * Build the consolidation prompt that instructs the agent to:
 * 1. Run Pass 2 (LLM cleaning) on the freshly cleansed transcript
 * 2. Write an episodic reflection
 * 3. Update MEMORY.md
 * 4. Run Pass 2 on any new Fireflies meeting transcripts
 */
function buildConsolidationPrompt(): string {
  return [
    "MEMORY CONSOLIDATION — SLEEP CYCLE",
    "",
    "Your session is about to be reset. Before your memory is wiped, you MUST consolidate your memories. Perform ALL of the following steps:",
    "",
    "## Step 1: Pass 2 — LLM Transcript Cleaning",
    "",
    "Check `memory/cleansed-sessions/` for the most recent cleansed transcript (Pass 1 was just completed deterministically). If found, apply Pass 2 LLM cleaning:",
    "- **Entity normalization**: Replace informal references with canonical names (e.g., 'the NS script' → 'reallocation_suitelet.js')",
    "- **Pronoun resolution**: Replace ambiguous 'it', 'that', 'this' with explicit referents",
    "- **Narrative collapsing**: Merge multi-turn back-and-forth into concise summaries",
    "- **Ambiguity marking**: Add [UNCLEAR] tags where meaning cannot be determined",
    "- Save the cleaned version back to the same file (overwrite in place)",
    "- If the `memory-consolidation` skill is available, follow its detailed instructions",
    "",
    "## Step 2: Episodic Reflection",
    "",
    "Write a structured reflection file to `memory/episodes/`:",
    "- Filename: `YYYYMMDD_HHMMSS.md` (current timestamp)",
    "- YAML frontmatter: type: episode, session_id, date, time_range, tags, outcome (success/partial/failure), salience (high/medium/low), trigger",
    "- Sections: What Happened, What Succeeded, What Failed, What's Pending, Key Decisions, Tools & Artifacts, Context & Connections",
    "- Be specific — name files, functions, decisions, and reasons",
    "- Link to previous episodes or decisions if relevant",
    "",
    "## Step 3: Semantic Memory Update",
    "",
    "Append to `MEMORY.md` any durable facts, preferences, entities, or decisions from this session. Append-only — never delete existing content.",
    "",
    "## Step 4: Fireflies Meeting Transcripts",
    "",
    "Check `memory/bpc_meetings/` for any meeting transcripts with YAML frontmatter (type: meeting, source: fireflies). For any that have NOT been cleaned yet (raw speaker-labeled format), apply Pass 2:",
    "- Normalize speaker names if aliases are known",
    "- Add section headers for topic changes",
    "- Summarize action items and decisions at the end",
    "- Mark [UNCLEAR] for any ambiguous references",
    "- Update the frontmatter to add `pass2: true` so they are not re-processed",
    "",
    "This is your LAST CHANCE before this session's context is lost forever. Write all files now.",
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
