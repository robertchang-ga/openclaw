/**
 * consolidation-writer.js
 *
 * Memory Consolidation Pipeline — Episodic Reflection & Semantic Memory Writer
 *
 * Deterministically processes session messages to generate:
 *   1. Episodic reflection file (memory/episodes/YYYYMMDD_HHMMSS.md)
 *   2. MEMORY.md append (semantic memory update)
 *
 * This runs from the before_reset hook where no agentic turn is available.
 * LLM enrichment happens during Pass 2 via SKILL.md.
 */

import fs from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const EPISODES_DIR = join(
  homedir(),
  ".openclaw",
  "workspace",
  "memory",
  "episodes"
);

const MEMORY_FILE = join(
  homedir(),
  ".openclaw",
  "workspace",
  "MEMORY.md"
);

// ---------------------------------------------------------------------------
// Message Analysis
// ---------------------------------------------------------------------------

/**
 * Extract text content from a message object.
 */
function extractText(message) {
  if (!message) return "";
  const content = message.content;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((p) => p.type === "text" && p.text)
      .map((p) => p.text)
      .join("\n");
  }
  return "";
}

/**
 * Analyze session messages to extract structured information for the episodic reflection.
 */
function analyzeSession(messages) {
  const userMessages = [];
  const agentMessages = [];
  const toolsUsed = new Set();
  const topics = new Set();
  const errors = [];
  const decisions = [];

  for (const msg of messages) {
    const role = msg.role;
    const text = extractText(msg);

    if (role === "user" && text) {
      userMessages.push(text);
      // Extract topics from user messages (first few words or first line)
      const firstLine = text.split("\n")[0].slice(0, 100);
      if (firstLine.length > 10) topics.add(firstLine);
    }

    if (role === "assistant" && text) {
      agentMessages.push(text);
      // Detect decisions (look for "I'll", "Let's", "decided", "choosing")
      if (/\b(I'll|Let's|decided|choosing|went with|opted for)\b/i.test(text)) {
        const firstSentence = text.split(/[.!?\n]/)[0].trim();
        if (firstSentence.length > 10 && firstSentence.length < 200) {
          decisions.push(firstSentence);
        }
      }
    }

    // Track tools used
    if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
        if ((part.type === "tool_use" || part.type === "function_call") && part.name) {
          toolsUsed.add(part.name);
        }
      }
    }

    // Track errors
    if (role === "assistant" && /\b(error|failed|bug|fix|issue|broken)\b/i.test(text)) {
      const errorLine = text.split("\n").find((l) =>
        /\b(error|failed|bug|fix|issue|broken)\b/i.test(l)
      );
      if (errorLine && errorLine.length < 200) {
        errors.push(errorLine.trim());
      }
    }
  }

  // Determine outcome
  const lastAgentMsg = agentMessages[agentMessages.length - 1] || "";
  const outcome =
    /\b(done|complete|finished|success|working|fixed|resolved)\b/i.test(lastAgentMsg)
      ? "success"
      : errors.length > 0
        ? "partial"
        : "success";

  // Determine salience based on session length and tool usage
  const salience =
    messages.length > 40 || toolsUsed.size > 5
      ? "high"
      : messages.length > 15
        ? "medium"
        : "low";

  // Extract tags from topics
  const tags = [...topics]
    .slice(0, 5)
    .map((t) => {
      // Extract key words for tags
      const words = t.toLowerCase().split(/\s+/).slice(0, 3).join("-");
      return words.replace(/[^a-z0-9-]/g, "");
    })
    .filter((t) => t.length > 2);

  return {
    userMessages,
    agentMessages,
    toolsUsed: [...toolsUsed],
    topics: [...topics],
    errors: errors.slice(0, 5),
    decisions: decisions.slice(0, 5),
    outcome,
    salience,
    tags,
    messageCount: messages.length,
  };
}

// ---------------------------------------------------------------------------
// Episodic Reflection Writer
// ---------------------------------------------------------------------------

/**
 * Generate the episodic reflection markdown from analyzed session data.
 */
function generateEpisodicReflection(analysis, meta) {
  const lines = [
    "---",
    "type: episode",
    `session_id: ${meta.sessionId}`,
    `cleansed_transcript: ${meta.cleansedFilename || "pending"}`,
    `date: ${meta.dateStr}`,
    `time_range: "${meta.timeRange}"`,
    `tags: [${analysis.tags.join(", ")}]`,
    `outcome: ${analysis.outcome}`,
    `salience: ${analysis.salience}`,
    `trigger: ${meta.trigger}`,
    "---",
    "",
    "## What Happened",
    "",
  ];

  // Summarize what happened from user messages
  const topicSummary = analysis.topics.slice(0, 3).map((t) => `- ${t}`).join("\n");
  if (topicSummary) {
    lines.push(topicSummary);
  } else {
    lines.push("- [Session with no extractable topics]");
  }

  lines.push("", "## What Succeeded", "");
  if (analysis.outcome === "success" || analysis.outcome === "partial") {
    lines.push(`- Session completed (${analysis.messageCount} messages exchanged)`);
    if (analysis.toolsUsed.length > 0) {
      lines.push(`- Used ${analysis.toolsUsed.length} distinct tools`);
    }
  } else {
    lines.push("- [No clear successes detected]");
  }

  lines.push("", "## What Failed", "");
  if (analysis.errors.length > 0) {
    for (const error of analysis.errors) {
      lines.push(`- ${error}`);
    }
  } else {
    lines.push("- [No failures detected]");
  }

  lines.push("", "## What's Pending", "");
  lines.push("- [ ] [Review and enrich this episodic reflection during Pass 2]");

  lines.push("", "## Key Decisions", "");
  if (analysis.decisions.length > 0) {
    for (const decision of analysis.decisions) {
      lines.push(`- ${decision}`);
    }
  } else {
    lines.push("- [No explicit decisions detected]");
  }

  lines.push("", "## Tools & Artifacts", "");
  if (analysis.toolsUsed.length > 0) {
    lines.push(`Tools used: \`${analysis.toolsUsed.join("`, `")}\``);
  } else {
    lines.push("- [No tools used]");
  }

  lines.push("", "## Context & Connections", "");
  lines.push("- [Connections to previous work will be added during Pass 2]");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// MEMORY.md Append
// ---------------------------------------------------------------------------

/**
 * Generate a semantic memory entry to append to MEMORY.md.
 */
function generateSemanticEntry(analysis, meta) {
  const lines = [
    "",
    `## Session ${meta.dateStr} ${meta.timeRange}`,
    "",
  ];

  if (analysis.topics.length > 0) {
    lines.push("### Topics");
    for (const topic of analysis.topics.slice(0, 5)) {
      lines.push(`- ${topic}`);
    }
    lines.push("");
  }

  if (analysis.decisions.length > 0) {
    lines.push("### Decisions");
    for (const decision of analysis.decisions) {
      lines.push(`- ${decision}`);
    }
    lines.push("");
  }

  if (analysis.toolsUsed.length > 0) {
    lines.push(`### Tools: \`${analysis.toolsUsed.join("`, `")}\``);
    lines.push("");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Run the forced consolidation step: write episodic reflection + update MEMORY.md.
 *
 * @param {object} params
 * @param {unknown[]} params.messages - Session messages from before_reset hook
 * @param {string} [params.sessionFile] - Path to the session file
 * @param {string} [params.reason] - Trigger reason (reset, new, overflow, midnight)
 * @param {string} [params.cleansedFilename] - Filename of corresponding cleansed transcript
 * @returns {{ episodePath: string | null, memoryUpdated: boolean }}
 */
export async function forceConsolidationTurn(params) {
  const messages = Array.isArray(params.messages) ? params.messages : [];

  if (messages.length === 0) {
    console.warn("[consolidation-writer] no messages to consolidate");
    return { episodePath: null, memoryUpdated: false };
  }

  // Analyze session
  const analysis = analyzeSession(messages);

  // Generate metadata
  const now = new Date();
  const dateStr = now.toISOString().split("T")[0];
  const timeStr = [
    String(now.getHours()).padStart(2, "0"),
    String(now.getMinutes()).padStart(2, "0"),
  ].join(":");
  const timeRange = `${timeStr} EST`;

  const timestamp = [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, "0"),
    String(now.getDate()).padStart(2, "0"),
    "_",
    String(now.getHours()).padStart(2, "0"),
    String(now.getMinutes()).padStart(2, "0"),
    String(now.getSeconds()).padStart(2, "0"),
  ].join("");

  // Extract sessionId from session file path or messages
  const sessionId = params.sessionFile
    ? params.sessionFile.split(/[/\\]/).pop()?.replace(/\.jsonl$/, "") || "unknown"
    : "unknown";

  const meta = {
    sessionId,
    dateStr,
    timeRange,
    trigger: params.reason || "manual",
    cleansedFilename: params.cleansedFilename || `${timestamp}.md`,
  };

  let episodePath = null;
  let memoryUpdated = false;

  // Write episodic reflection
  try {
    const episodeContent = generateEpisodicReflection(analysis, meta);
    const episodeFilename = `${timestamp}.md`;
    episodePath = join(EPISODES_DIR, episodeFilename);

    await fs.mkdir(EPISODES_DIR, { recursive: true });
    await fs.writeFile(episodePath, episodeContent, "utf-8");
    console.log(`[consolidation-writer] episodic reflection → ${episodePath}`);
  } catch (err) {
    console.error(`[consolidation-writer] failed to write episodic reflection: ${String(err)}`);
  }

  // Append to MEMORY.md
  try {
    const semanticEntry = generateSemanticEntry(analysis, meta);

    // Ensure parent directory exists
    const memoryDir = MEMORY_FILE.split(/[/\\]/).slice(0, -1).join("/");
    await fs.mkdir(memoryDir, { recursive: true });

    // Read existing content to check if header exists
    let existing = "";
    try {
      existing = await fs.readFile(MEMORY_FILE, "utf-8");
    } catch {
      // File doesn't exist yet — will be created
    }

    if (!existing.trim()) {
      // Initialize MEMORY.md with header
      await fs.writeFile(
        MEMORY_FILE,
        `# Semantic Memory\n\nDurable facts, preferences, entities, and decisions.\n${semanticEntry}`,
        "utf-8"
      );
    } else {
      // Append
      await fs.appendFile(MEMORY_FILE, semanticEntry, "utf-8");
    }
    memoryUpdated = true;
    console.log("[consolidation-writer] MEMORY.md updated");
  } catch (err) {
    console.error(`[consolidation-writer] failed to update MEMORY.md: ${String(err)}`);
  }

  return { episodePath, memoryUpdated };
}

export default { forceConsolidationTurn };
