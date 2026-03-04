/**
 * transcript-cleaner.js
 *
 * Memory Consolidation Pipeline — Transcript Cleaner
 *
 * Converts raw JSONL session transcripts into clean, structured markdown.
 * Two-pass design:
 *   Pass 1 (deterministic, zero LLM cost) — strips noise, preserves significant outputs
 *   Pass 2 (LLM) — entity normalization, pronoun resolution, narrative collapsing
 *
 * Usage:
 *   import { cleanseTranscript } from './transcript-cleaner.js';
 *   const result = await cleanseTranscript(sessionFilePath, options);
 */

import fs from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CLEANSED_SESSIONS_DIR = join(homedir(), ".openclaw", "workspace", ".staging", "sessions");

/** Entry types to skip entirely (non-message metadata). */
const SKIP_TYPES = new Set([
  "session",
  "model_change",
  "thinking_level_change",
  "custom",
  "reasoning_level_change",
]);

/** Metadata fields to strip from entries. */
const _METADATA_FIELDS = [
  "textSignature",
  "thoughtSignature",
  "usage",
  "cost",
  "api",
  "provider",
  "model",
  "stopReason",
  "providerMeta",
  "apiMeta",
  "modelMeta",
];

/** Regex patterns for noise to strip from message content. */
const CONTENT_NOISE_PATTERNS = [
  // Conversation info + Sender JSON blocks (injected into user messages)
  /Conversation info:\s*```json[\s\S]*?```\s*/g,
  /Sender:\s*```json[\s\S]*?```\s*/g,
  // <final>[[reply_to_current]] wrapper
  /<final>\[\[reply_to_current\]\]/g,
  /\[\[reply_to_current\]\]\s*/g,
  // <final> and </final> tags (keep content, strip tags)
  /<\/?final>/g,
  // <cognee_memories> blocks (injected recalls)
  /<cognee_memories>[\s\S]*?<\/cognee_memories>\s*/g,
  // Config warnings (plugin id mismatch, etc.)
  /⚠️\s*Warning:.*plugin id mismatch.*\n?/gi,
  // Repetitive system noise
  /\[System\]\s*Plugin.*loaded.*\n?/gi,
  // Embedded timestamps (redundant with per-turn [HH:MM UTC] prefix)
  // e.g., [Wed 2026-02-04 14:26 UTC] or [Mon 2026-03-01 09:15 UTC]
  /\[\w{3}\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+UTC\]\s*/g,
  // Message ID metadata lines
  /\[message_id:\s*[0-9a-f-]+\]\s*/gi,
  // External content blocks (web_search, web_fetch output wrapped by external-content.ts)
  // Matches: <<<EXTERNAL_UNTRUSTED_CONTENT id="...">>>> ... <<<END_EXTERNAL_UNTRUSTED_CONTENT id="...">>>
  /<<<EXTERNAL_UNTRUSTED_CONTENT[\s\S]*?<<<END_EXTERNAL_UNTRUSTED_CONTENT[^>]*>>>/g,
  // Standalone external content warning blocks
  /⚠️\s*CAUTION:[\s\S]*?Do not execute[\s\S]*?\n/gi,
  // Raw JSON objects leaked into chat (e.g., web_search results without markers)
  /\{\s*"query"[\s\S]*?"results"\s*:\s*\[[\s\S]*?\]\s*\}/g,
];

/** Tool names whose output is ephemeral (scaffolding, not significant). */
const EPHEMERAL_TOOLS = new Set([
  "read_file",
  "read",
  "view_file",
  "list_dir",
  "find_file",
  "cat",
  "ls",
  "pwd",
  "get_config",
  "check_config",
  "read_config",
  "which",
  "type",
  "where",
  "file",
  "web_search",
  "web_fetch",
  "fetch",
  "search",
  "brave_search",
  "memory_search",
  "memory_get",
  "cognee_search",
  "cognee_datasets",
]);

/**
 * Format an entry timestamp as a short time label for inline display.
 * Returns " [HH:MM UTC]" or "" if the timestamp can't be parsed.
 */
function formatEntryTime(ts) {
  try {
    const d = typeof ts === "number" ? new Date(ts) : new Date(ts);
    if (isNaN(d.getTime())) {
      return "";
    }
    const h = d.getUTCHours().toString().padStart(2, "0");
    const m = d.getUTCMinutes().toString().padStart(2, "0");
    return `[${h}:${m} UTC] `;
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Pass 1: Deterministic Cleaning
// ---------------------------------------------------------------------------

/**
 * Parse JSONL file into an array of entries.
 */
async function parseJsonlFile(filePath) {
  const content = await fs.readFile(filePath, "utf-8");
  const entries = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    try {
      entries.push(JSON.parse(trimmed));
    } catch {
      // Skip malformed lines
    }
  }
  return entries;
}

/**
 * Build the conversation chain by walking the linked list (id → parentId).
 * Returns entries in parent→child order (chronological).
 * Orphaned entries (broken parentId) are appended at the end with a marker.
 */
function buildChain(entries) {
  if (entries.length === 0) {
    return [];
  }

  // Build lookup maps
  const byId = new Map();
  const childrenOf = new Map(); // parentId → [entry]
  for (const entry of entries) {
    if (entry.id) {
      byId.set(entry.id, entry);
    }
    const pid = entry.parentId;
    if (pid) {
      if (!childrenOf.has(pid)) {
        childrenOf.set(pid, []);
      }
      childrenOf.get(pid).push(entry);
    }
  }

  // Find root: entry whose parentId is missing or not in the file
  const roots = entries.filter((e) => !e.parentId || !byId.has(e.parentId));

  // Walk from root(s) in order
  const visited = new Set();
  const ordered = [];

  function walk(entry) {
    if (!entry || visited.has(entry.id)) {
      return;
    }
    visited.add(entry.id);
    ordered.push(entry);
    // Follow children (main branch = last child for retries)
    const children = childrenOf.get(entry.id) || [];
    if (children.length === 1) {
      walk(children[0]);
    } else if (children.length > 1) {
      // On forks, follow the main branch (last child = most recent)
      // But walk all branches to capture everything
      for (const child of children) {
        walk(child);
      }
    }
  }

  for (const root of roots) {
    walk(root);
  }

  // Collect orphans (entries not reached by walking)
  const orphans = entries.filter((e) => e.id && !visited.has(e.id));
  for (const orphan of orphans) {
    orphan._orphaned = true;
    ordered.push(orphan);
  }

  if (orphans.length > 0) {
    console.warn(
      `[transcript-cleaner] ${orphans.length} orphaned entries found (broken parentId chain)`,
    );
  }

  return ordered;
}

/**
 * Extract text content from a message entry's content field.
 * Handles both string content and array-of-parts content.
 */
function extractTextContent(message) {
  if (!message?.content) {
    return "";
  }
  if (typeof message.content === "string") {
    return message.content;
  }
  if (Array.isArray(message.content)) {
    const parts = [];
    for (const part of message.content) {
      if (part.type === "text" && part.text) {
        parts.push(part.text);
      } else if (part.type === "tool_result") {
        // Tool result content may be a string or array of content blocks
        if (typeof part.content === "string") {
          parts.push(part.content);
        } else if (Array.isArray(part.content)) {
          for (const sub of part.content) {
            if (sub.type === "text" && sub.text) {
              parts.push(sub.text);
            }
          }
        }
      }
      // tool_use / function_call / function_response parts are handled
      // by processEntry's tool tracking logic, not here
    }
    return parts.join("\n");
  }
  return "";
}

/**
 * Check if a tool call output is "significant" (not ephemeral scaffolding).
 * Significant outputs are preserved; ephemeral ones are summarized.
 */
function isSignificantToolOutput(toolName) {
  return !EPHEMERAL_TOOLS.has(toolName.toLowerCase());
}

/**
 * Strip noise patterns from text content.
 */
function stripContentNoise(text) {
  let cleaned = text;
  for (const pattern of CONTENT_NOISE_PATTERNS) {
    cleaned = cleaned.replace(pattern, "");
  }
  return cleaned.trim();
}

/**
 * Check if an assistant message is empty (signature-only, no real text).
 */
function isEmptyAssistantTurn(entry) {
  if (entry.message?.role !== "assistant") {
    return false;
  }
  const text = extractTextContent(entry.message);
  return !text || text.trim().length === 0;
}

/**
 * Process a single entry and return a markdown fragment, or null to skip.
 */
function processEntry(entry) {
  const type = entry.type;

  // Skip non-message types
  if (SKIP_TYPES.has(type)) {
    return null;
  }

  // Handle compaction entries specially — preserve summary + timestamp
  if (type === "compaction") {
    const summary = entry.summary || entry.message?.content || "[no summary]";
    const ts = entry.timestamp || entry.createdAt || "unknown time";
    return `\n---\n**[Compaction Summary — ${ts}]**\n${summary}\n---\n`;
  }

  // Skip entries without messages
  if (type !== "message" || !entry.message) {
    return null;
  }

  const message = entry.message;
  const role = message.role;

  // Skip empty assistant turns
  if (role === "assistant" && isEmptyAssistantTurn(entry)) {
    return null;
  }

  // Extract and clean text
  let text = extractTextContent(message);
  text = stripContentNoise(text);

  if (!text && role !== "assistant") {
    return null;
  }
  // Skip agent turns that are just "(no output)" or empty after cleaning
  if (role === "assistant" && (!text || text.trim().toLowerCase() === "(no output)")) {
    return null;
  }

  // Format with speaker labels and timestamp
  const speaker = role === "user" ? "[User]" : "[Agent]";
  const ts = entry.timestamp || entry.createdAt;
  const timeLabel = ts ? formatEntryTime(ts) : "";

  // Handle tool use in assistant messages
  const toolCalls = [];
  if (Array.isArray(message.content)) {
    for (const part of message.content) {
      if (part.type === "tool_use" || part.type === "function_call") {
        const toolName = part.name || part.function?.name || "unknown_tool";
        if (isSignificantToolOutput(toolName)) {
          toolCalls.push(`  - Used tool: \`${toolName}\``);
        }
      }
    }
  }

  // Handle tool results
  if (role === "tool" || message.role === "tool") {
    const toolName = entry.toolName || message.name || "tool";
    if (!isSignificantToolOutput(toolName)) {
      return null; // Skip ephemeral tool results entirely
    }
    // Skip tool results that contain YAML frontmatter (e.g., skill files)
    if (text.trimStart().startsWith("---\n")) {
      return null;
    }
    // Truncate very long tool results
    const maxLen = 2000;
    const resultText = text.length > maxLen ? text.slice(0, maxLen) + "\n[...truncated]" : text;
    return `\n> **Tool result** (\`${toolName}\`):\n> ${resultText.split("\n").join("\n> ")}\n`;
  }

  // Build the output — [HH:MM UTC] [Speaker]: text
  let output = `${timeLabel}${speaker}: ${text}`;
  if (toolCalls.length > 0) {
    output += "\n" + toolCalls.join("\n");
  }

  // Mark orphaned entries
  if (entry._orphaned) {
    output = `\n[Orphaned Entry]\n${output}`;
  }

  return output;
}

/**
 * Generate session metadata for the frontmatter.
 */
function generateSessionMeta(entries) {
  const firstEntry = entries.find((e) => e.timestamp || e.createdAt);
  const lastEntry = [...entries].toReversed().find((e) => e.timestamp || e.createdAt);

  const startTime = firstEntry?.timestamp || firstEntry?.createdAt || new Date().toISOString();
  const endTime = lastEntry?.timestamp || lastEntry?.createdAt || startTime;

  const startDate = new Date(startTime);
  const endDate = new Date(endTime);

  // sessionId may live on the "session" type entry (which is in SKIP_TYPES),
  // so we search all raw entries, not just filtered ones.
  const sessionId = entries.find((e) => e.sessionId)?.sessionId || "unknown";

  const formatTime = (d) => {
    const h = d.getUTCHours().toString().padStart(2, "0");
    const m = d.getUTCMinutes().toString().padStart(2, "0");
    return `${h}:${m}`;
  };

  const dateStr = startDate.toISOString().split("T")[0];
  const timeRange = `${formatTime(startDate)}-${formatTime(endDate)} UTC`;

  return { dateStr, timeRange, sessionId, startDate };
}

/**
 * Collapse consecutive duplicate messages from the same speaker.
 * E.g., 5× "[HH:MM UTC] [User]: Hey hey!" → single "[HH:MM UTC] [User]: Hey hey! (×5, until HH:MM UTC)"
 */
function collapseConsecutiveDuplicates(fragments) {
  if (fragments.length <= 1) {
    return fragments;
  }

  // Regex to parse "[HH:MM UTC] [Speaker]: text" lines
  const lineRe = /^\[(\d{2}:\d{2}) UTC\] (\[[^\]]+\]): (.+)$/s;

  const result = [];
  let i = 0;
  while (i < fragments.length) {
    const match = fragments[i].match(lineRe);
    if (!match) {
      result.push(fragments[i]);
      i++;
      continue;
    }
    const [, firstTime, speaker, text] = match;
    const normalizedText = text.trim().toLowerCase();
    let lastTime = firstTime;
    let count = 1;

    // Look ahead for consecutive duplicates
    while (i + count < fragments.length) {
      const nextMatch = fragments[i + count].match(lineRe);
      if (!nextMatch) {
        break;
      }
      const [, nextTime, nextSpeaker, nextText] = nextMatch;
      if (nextSpeaker !== speaker || nextText.trim().toLowerCase() !== normalizedText) {
        break;
      }
      lastTime = nextTime;
      count++;
    }

    if (count >= 3) {
      // Collapse 3+ consecutive duplicates
      result.push(
        `[${firstTime} UTC] ${speaker}: ${text.trim()} (×${count}, until ${lastTime} UTC)`,
      );
    } else {
      // Keep 1-2 as-is
      for (let j = 0; j < count; j++) {
        result.push(fragments[i + j]);
      }
    }
    i += count;
  }
  return result;
}

/**
 * Run Pass 1: deterministic cleaning.
 * Returns a clean markdown string.
 */
async function pass1(filePath) {
  const rawEntries = await parseJsonlFile(filePath);

  if (rawEntries.length === 0) {
    return { markdown: "", meta: null, entryCount: 0 };
  }

  // Build chronological chain
  const ordered = buildChain(rawEntries);

  // Generate metadata
  const meta = generateSessionMeta(ordered);

  // Process each entry
  const fragments = [];
  for (const entry of ordered) {
    const fragment = processEntry(entry);
    if (fragment) {
      fragments.push(fragment);
    }
  }

  // Build frontmatter
  const frontmatter = [
    "---",
    "type: session",
    `session_id: ${meta.sessionId}`,
    `date: ${meta.dateStr}`,
    `time_range: "${meta.timeRange}"`,
    "---",
  ].join("\n");

  // Collapse consecutive duplicate messages from the same speaker
  const collapsed = collapseConsecutiveDuplicates(fragments);

  const markdown = frontmatter + "\n" + collapsed.join("\n");

  return {
    markdown,
    meta,
    entryCount: ordered.length,
    processedCount: fragments.length,
    orphanCount: ordered.filter((e) => e._orphaned).length,
  };
}

// ---------------------------------------------------------------------------
// Pass 2: LLM Cleaning (stub — implemented via SKILL.md agent turn)
// ---------------------------------------------------------------------------

// Pass 2 is handled by the agent via the memory-consolidation SKILL.
// It receives the Pass 1 output and applies:
//   min: entity normalization (lookup + LLM for unknowns)
//   full: + pronoun resolution, narrative collapsing, ambiguity marking
//
// This is triggered as an agentic turn, not inline here.

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Cleanse a session transcript (JSONL → markdown).
 *
 * @param {string} sessionFilePath - Path to the raw .jsonl session file
 * @param {object} options
 * @param {string} [options.outputDir] - Override output directory
 * @param {object} [options.logger] - Optional logger (default: console)
 * @returns {{ outputPath: string, stats: object }}
 */
export async function cleanseTranscript(sessionFilePath, options = {}) {
  const outputDir = options.outputDir || CLEANSED_SESSIONS_DIR;
  const log = options.logger || console;

  // Run Pass 1
  const result = await pass1(sessionFilePath);

  if (!result.meta) {
    (log.warn || log.log).call(log, "[transcript-cleaner] empty session file, nothing to cleanse");
    return { outputPath: null, stats: { entryCount: 0 } };
  }

  // Generate output filename from session start time (UTC)
  const ts = result.meta.startDate;
  const timestamp = [
    ts.getUTCFullYear(),
    String(ts.getUTCMonth() + 1).padStart(2, "0"),
    String(ts.getUTCDate()).padStart(2, "0"),
    "_",
    String(ts.getUTCHours()).padStart(2, "0"),
    String(ts.getUTCMinutes()).padStart(2, "0"),
    String(ts.getUTCSeconds()).padStart(2, "0"),
  ].join("");
  const outputPath = join(outputDir, `${timestamp}.md`);

  // Ensure output directory exists
  await fs.mkdir(outputDir, { recursive: true });

  // Write Pass 1 output
  await fs.writeFile(outputPath, result.markdown, "utf-8");

  (log.info || log.log).call(
    log,
    `[transcript-cleaner] Pass 1 complete: ${result.entryCount} entries → ` +
      `${result.processedCount} fragments, ${result.orphanCount} orphans → ${outputPath}`,
  );

  return {
    outputPath,
    stats: {
      entryCount: result.entryCount,
      processedCount: result.processedCount,
      orphanCount: result.orphanCount,
    },
  };
}

export default { cleanseTranscript };

// Named exports for testing
export {
  buildChain,
  stripContentNoise,
  processEntry,
  generateSessionMeta,
  isSignificantToolOutput,
  extractTextContent,
};
