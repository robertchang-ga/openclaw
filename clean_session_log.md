---
name: clean-session-log
description: Clean OpenClaw session JSONL logs before ingesting into Cognee. Use this skill whenever the user wants to clean, prepare, or pre-process session logs for memory indexing, mentions cleaning raw agent logs, wants to strip noise from JSONL files, or is improving Cognee ingestion quality. Handles both a standalone script and an on-demand cleaning workflow. Trigger this skill for any task involving OpenClaw log cleaning, Cognee pre-processing, or session log preparation.
---

# clean-session-log

Cleans OpenClaw `.jsonl` session logs for high-quality Cognee ingestion using a two-pass pipeline:

1. **Deterministic pass** — fast, free, no LLM:
   - Strips `<cognee-memory>...</cognee-memory>` injection blocks
   - Removes `<function_calls>` / `<function_results>` XML scaffolding (preserves inner data)
   - Removes injected system prompt boilerplate
   - Drops noise turns: status messages, empty turns, filler responses
   - Deduplicates near-identical consecutive turns

2. **LLM pass** (claude-haiku, cheap) — handles the rest:
   - Normalizes entity names (NetSuite, Balsam Brands, etc.)
   - Fixes unambiguous ASR errors
   - Resolves clear pronoun references
   - Collapses interrupted/restarted sentences
   - Marks genuinely ambiguous spans as `[UNCLEAR: ...]` rather than guessing

**Key principle**: Cleaning, not summarizing. All facts, names, decisions, and specifics are preserved verbatim. Only noise and structural artifacts are removed.

---

## When the user wants to clean a specific log file

Run the script directly:

```bash
python scripts/clean_session_log.py <path/to/session.jsonl>
```

This produces `<path/to/session_cleaned.jsonl>` alongside the input.

### Common options

```bash
# Deterministic only (no LLM cost, good for high-volume batch)
python scripts/clean_session_log.py session.jsonl --no-llm

# Preview first 5 turns and stats without writing output
python scripts/clean_session_log.py session.jsonl --dry-run

# Custom output path
python scripts/clean_session_log.py session.jsonl --output /path/to/output.jsonl

# Larger batches for long sessions (default: 20 turns per LLM call)
python scripts/clean_session_log.py session.jsonl --batch-size 40
```

Requires `ANTHROPIC_API_KEY` in environment for the LLM pass.

---

## When the user wants to set up a post-session hook

Add to OpenClaw's session lifecycle config (`~/.openclaw/config.yaml`):

```yaml
hooks:
  post_session:
    - name: clean-and-index
      run: |
        python /path/to/scripts/clean_session_log.py "$SESSION_LOG" \
          --output "$SESSION_LOG_CLEANED"
        cognee add "$SESSION_LOG_CLEANED" --dataset sessions
        cognee cognify --dataset sessions
```

This runs automatically after every session ends: cleans the log, then feeds
the cleaned output to Cognee for indexing.

---

## When the user wants to batch-process existing logs

```bash
# Clean all JSONL files in a directory
for f in ~/.openclaw/logs/*.jsonl; do
  python scripts/clean_session_log.py "$f"
done

# Then ingest all cleaned files
cognee add ~/.openclaw/logs/*_cleaned.jsonl --dataset sessions
cognee cognify --dataset sessions
```

---

## Input format

Each line in the `.jsonl` file should be a JSON object with at minimum:
```json
{"role": "user", "content": "..."}
{"role": "assistant", "content": "..."}
```

Additional fields (timestamps, session IDs, etc.) are preserved unchanged.
Content can also be an array of `{type, text}` blocks — the script handles both formats.

---

## Understanding the output

- `[UNCLEAR: original text]` — LLM flagged this span as too unclear to clean
  safely. Review manually before ingestion or leave as-is (Cognee will still
  index it, just with lower confidence edges).
- Stats printed at end: input turns → after deterministic → after dedup → final.
  A 30–60% reduction is typical for voice sessions; text sessions usually see 15–30%.

---

## Extending the deterministic rules

To add more noise patterns, edit the constants at the top of `scripts/clean_session_log.py`:

- `NOISE_PHRASES` — exact short strings to drop (lowercase, with punctuation)
- `STATUS_PATTERNS` — regex patterns matched against turn content start
- `SYSTEM_PROMPT_MARKERS` — line prefixes that signal injected boilerplate

To tune the LLM cleaning instructions (e.g. add domain-specific entity names),
edit `LLM_SYSTEM_PROMPT` in the same file.
