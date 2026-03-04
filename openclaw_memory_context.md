# OpenClaw Memory Enhancement — Session Context

## Background

OpenClaw is an open-source TypeScript AI agent framework. Its native memory
system is Markdown-based: a `MEMORY.md` working memory file and session
summaries written to a `memory/` folder. This is flat and lossy by design.

Cognee has been integrated via the official `@cognee/cognee-openclaw` plugin
with `autoRecall: true` and `autoIndex: true`. However, the plugin currently
only indexes files under the `memory/` folder — meaning Cognee's knowledge
graph is built on top of pre-summarized content rather than raw session data.
This limits graph quality because summarization discards entity names,
decisions, and relationship signals before Cognee ever sees them.

---

## What We're Trying to Do

Feed Cognee cleaned raw session logs instead of (or in addition to) Markdown
summaries, so its entity extraction and graph construction have full signal.

The key principle: **clean, don't summarize**. Cognee should do the compression
into graph structure itself. Our job is to strip noise while preserving every
fact, name, decision, and relationship.

---

## The Cleaning Pipeline

A two-pass pipeline implemented in `clean_session_log.py`:

**Pass 1 — Deterministic (free, fast):**

- Strips `<cognee_memories>...</cognee_memories>` injection blocks (autoRecall inserts these at session start; re-ingesting them would create circular/duplicate graph nodes)
- Removes `<function_calls>` / `<fnr>` XML scaffolding while preserving inner data content
- Drops injected system prompt boilerplate
- Drops noise turns: status messages ("Memory indexed successfully"), empty turns, filler responses ("One moment.", "Got it.")
- Deduplicates near-identical consecutive turns within a sliding window

**Pass 2 — LLM:**

- Normalizes entity names (netsuite/NetSute/net suite → NetSuite, etc.)
- Fixes unambiguous ASR errors from voice transcripts
- Resolves clear pronoun references ("fix it" → "fix the NetSuite integration")
- Collapses interrupted/restarted sentences into clean single sentences
- Marks ambiguous spans as `[UNCLEAR: original text]` rather than guessing

**Input format:** `.jsonl` — one JSON turn per line with `role` and `content` fields, plus any metadata fields which are preserved unchanged.

**Output:** cleaned `.jsonl` ready for `cognee.add()`.

---

## Files

- `clean_session_log.py` — the standalone script, run directly or wired into a post-session hook
- `clean-session-log.skill` — OpenClaw skill that wraps the script so the agent can invoke cleaning on-demand or as part of its session lifecycle

---

## Intended Integration

Post-session hook in `~/.openclaw/config.yaml`:

```yaml
hooks:
  post_session:
    - name: clean-and-index
      run: |
        python clean_session_log.py "$SESSION_LOG" --output "$SESSION_LOG_CLEANED"
        cognee add "$SESSION_LOG_CLEANED" --dataset sessions
        cognee cognify --dataset sessions
```

This replaces the current flow (summaries → Cognee) with:
raw log → deterministic strip → LLM clean → Cognee graph

---

## What's Not Done Yet

- The `SYSTEM_PROMPT_MARKERS` list in the script needs to be verified against
  actual OpenClaw log output — the current values are educated guesses
- The `<cognee_memories>` tag delimiter needs to be confirmed from a real log
- The LLM pass system prompt can be seeded with domain-specific entity names
  (Balsam Brands, NetSuite, MuleSoft, HSBC Bermuda, etc.) to improve
  normalization consistency
- Broader Cognee dataset strategy: sessions vs. documents vs. memory/ — whether
  these stay as separate datasets or merge is TBD
