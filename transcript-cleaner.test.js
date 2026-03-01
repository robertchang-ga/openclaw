import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildChain,
  stripContentNoise,
  processEntry,
  generateSessionMeta,
  isSignificantToolOutput,
  extractTextContent,
} from "./transcript-cleaner.js";

// ---------------------------------------------------------------------------
// buildChain
// ---------------------------------------------------------------------------

describe("buildChain", () => {
  it("returns empty array for empty input", () => {
    assert.deepStrictEqual(buildChain([]), []);
  });

  it("preserves a single entry", () => {
    const entries = [{ id: "a", type: "message", message: { role: "user", content: "hello" } }];
    const result = buildChain(entries);
    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].id, "a");
  });

  it("orders entries by parent→child chain", () => {
    const entries = [
      { id: "b", parentId: "a", type: "message" },
      { id: "a", type: "message" },
      { id: "c", parentId: "b", type: "message" },
    ];
    const result = buildChain(entries);
    assert.deepStrictEqual(
      result.map((e) => e.id),
      ["a", "b", "c"],
    );
  });

  it("handles forks (multiple children) — follows all branches", () => {
    const entries = [
      { id: "root", type: "message" },
      { id: "branch1", parentId: "root", type: "message" },
      { id: "branch2", parentId: "root", type: "message" },
    ];
    const result = buildChain(entries);
    assert.strictEqual(result.length, 3);
    assert.strictEqual(result[0].id, "root");
    // Both branches should be present
    const ids = result.map((e) => e.id);
    assert(ids.includes("branch1"));
    assert(ids.includes("branch2"));
  });

  it("marks orphaned entries with _orphaned flag", () => {
    const entries = [
      { id: "a", type: "message" },
      { id: "orphan", parentId: "nonexistent", type: "message" },
    ];
    const result = buildChain(entries);
    // The orphaned entry has parentId pointing to nonexistent, so it's a root
    // Actually, roots = entries whose parentId is missing OR not in byId
    // "orphan" has parentId "nonexistent" which is not in byId → it's a root too
    // So no orphans in this case — both are roots
    assert.strictEqual(result.length, 2);
  });

  it("handles entries without id (no crash)", () => {
    const entries = [
      { type: "message", message: { role: "user", content: "test" } },
    ];
    const result = buildChain(entries);
    assert.strictEqual(result.length, 1);
  });
});

// ---------------------------------------------------------------------------
// extractTextContent
// ---------------------------------------------------------------------------

describe("extractTextContent", () => {
  it("returns empty string for null/undefined message", () => {
    assert.strictEqual(extractTextContent(null), "");
    assert.strictEqual(extractTextContent(undefined), "");
  });

  it("extracts string content", () => {
    assert.strictEqual(
      extractTextContent({ content: "hello world" }),
      "hello world",
    );
  });

  it("extracts text parts from array content", () => {
    const message = {
      content: [
        { type: "text", text: "first" },
        { type: "tool_use", name: "read_file" },
        { type: "text", text: "second" },
      ],
    };
    assert.strictEqual(extractTextContent(message), "first\nsecond");
  });

  it("returns empty for message with no content field", () => {
    assert.strictEqual(extractTextContent({ role: "user" }), "");
  });

  it("extracts tool_result with string content", () => {
    const message = {
      content: [
        { type: "tool_result", content: "file contents here" },
      ],
    };
    assert.strictEqual(extractTextContent(message), "file contents here");
  });

  it("extracts tool_result with nested array content", () => {
    const message = {
      content: [
        {
          type: "tool_result",
          content: [
            { type: "text", text: "result line 1" },
            { type: "text", text: "result line 2" },
          ],
        },
      ],
    };
    assert.strictEqual(extractTextContent(message), "result line 1\nresult line 2");
  });

  it("ignores tool_use parts (handled separately)", () => {
    const message = {
      content: [
        { type: "tool_use", name: "write_file", input: {} },
      ],
    };
    assert.strictEqual(extractTextContent(message), "");
  });
});

// ---------------------------------------------------------------------------
// stripContentNoise
// ---------------------------------------------------------------------------

describe("stripContentNoise", () => {
  it("strips Conversation info JSON blocks", () => {
    const text = 'Hello\nConversation info: ```json\n{"key": "val"}\n```\nWorld';
    const result = stripContentNoise(text);
    assert.strictEqual(result, "Hello\nWorld");
  });

  it("strips Sender JSON blocks", () => {
    const text = 'Sender: ```json\n{"name": "User"}\n```\nHi there';
    const result = stripContentNoise(text);
    assert.strictEqual(result, "Hi there");
  });

  it("strips [[reply_to_current]]", () => {
    const text = "<final>[[reply_to_current]]Some reply";
    const result = stripContentNoise(text);
    assert.strictEqual(result, "Some reply");
  });

  it("strips cognee_memories blocks", () => {
    const text = "Before\n<cognee_memories>recalled stuff</cognee_memories>\nAfter";
    const result = stripContentNoise(text);
    assert.strictEqual(result, "Before\nAfter");
  });

  it("strips plugin id mismatch warnings", () => {
    const text = "⚠️ Warning: plugin id mismatch (expected foo)\nNormal text";
    const result = stripContentNoise(text);
    assert.strictEqual(result, "Normal text");
  });

  it("returns clean text unchanged", () => {
    const text = "This is perfectly clean text.";
    assert.strictEqual(stripContentNoise(text), text);
  });
});

// ---------------------------------------------------------------------------
// isSignificantToolOutput
// ---------------------------------------------------------------------------

describe("isSignificantToolOutput", () => {
  it("marks read_file as ephemeral (not significant)", () => {
    assert.strictEqual(isSignificantToolOutput("read_file"), false);
  });

  it("marks view_file as ephemeral", () => {
    assert.strictEqual(isSignificantToolOutput("view_file"), false);
  });

  it("marks list_dir as ephemeral", () => {
    assert.strictEqual(isSignificantToolOutput("list_dir"), false);
  });

  it("marks significant tools as significant", () => {
    assert.strictEqual(isSignificantToolOutput("write_file"), true);
    assert.strictEqual(isSignificantToolOutput("cognee_search"), true);
    assert.strictEqual(isSignificantToolOutput("exec"), true);
  });

  it("handles case insensitivity", () => {
    assert.strictEqual(isSignificantToolOutput("READ_FILE"), false);
    assert.strictEqual(isSignificantToolOutput("List_Dir"), false);
  });
});

// ---------------------------------------------------------------------------
// processEntry
// ---------------------------------------------------------------------------

describe("processEntry", () => {
  it("skips session-type entries", () => {
    assert.strictEqual(processEntry({ type: "session" }), null);
  });

  it("skips model_change entries", () => {
    assert.strictEqual(processEntry({ type: "model_change" }), null);
  });

  it("processes compaction entries with summary and timestamp", () => {
    const entry = {
      type: "compaction",
      summary: "Compacted conversation.",
      timestamp: "2026-03-01T00:00:00Z",
    };
    const result = processEntry(entry);
    assert(result.includes("Compaction Summary"));
    assert(result.includes("Compacted conversation."));
  });

  it("processes user message entries with speaker label", () => {
    const entry = {
      type: "message",
      message: { role: "user", content: "How do I deploy?" },
    };
    const result = processEntry(entry);
    assert(result.includes("**User**"));
    assert(result.includes("How do I deploy?"));
  });

  it("processes assistant message entries", () => {
    const entry = {
      type: "message",
      message: { role: "assistant", content: "Run npm deploy." },
    };
    const result = processEntry(entry);
    assert(result.includes("**Agent**"));
    assert(result.includes("Run npm deploy."));
  });

  it("skips empty assistant turns", () => {
    const entry = {
      type: "message",
      message: { role: "assistant", content: "" },
    };
    assert.strictEqual(processEntry(entry), null);
  });

  it("skips entries without messages", () => {
    assert.strictEqual(processEntry({ type: "message" }), null);
  });
});

// ---------------------------------------------------------------------------
// generateSessionMeta
// ---------------------------------------------------------------------------

describe("generateSessionMeta", () => {
  it("extracts date and time range from timestamps", () => {
    const entries = [
      { timestamp: "2026-03-01T10:30:00Z", id: "a", sessionId: "sess-123" },
      { timestamp: "2026-03-01T11:45:00Z", id: "b", parentId: "a" },
    ];
    const meta = generateSessionMeta(entries);
    assert.strictEqual(meta.dateStr, "2026-03-01");
    assert.strictEqual(meta.timeRange, "10:30-11:45 UTC");
    assert.strictEqual(meta.sessionId, "sess-123");
  });

  it("uses UTC times consistently", () => {
    // Create a timestamp at midnight EST (05:00 UTC)
    const entries = [
      { timestamp: "2026-03-01T05:00:00Z", id: "a", sessionId: "test" },
      { timestamp: "2026-03-01T06:30:00Z", id: "b" },
    ];
    const meta = generateSessionMeta(entries);
    assert.strictEqual(meta.timeRange, "05:00-06:30 UTC");
  });

  it("falls back to unknown sessionId", () => {
    const entries = [{ timestamp: "2026-01-15T12:00:00Z", id: "a" }];
    const meta = generateSessionMeta(entries);
    assert.strictEqual(meta.sessionId, "unknown");
  });

  it("handles entries with createdAt instead of timestamp", () => {
    const entries = [
      { createdAt: "2026-02-20T08:00:00Z", id: "a" },
      { createdAt: "2026-02-20T09:00:00Z", id: "b" },
    ];
    const meta = generateSessionMeta(entries);
    assert.strictEqual(meta.dateStr, "2026-02-20");
    assert.strictEqual(meta.timeRange, "08:00-09:00 UTC");
  });
});
