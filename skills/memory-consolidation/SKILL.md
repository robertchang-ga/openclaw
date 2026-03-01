---
name: memory-consolidation
description: >-
  Instructions for the LLM cleaning pass during memory consolidation.
  You are given a deterministically cleaned transcript and must normalize
  entities, resolve pronouns, collapse retries, and preserve ambiguity.
  This skill also documents the sleep cycle architecture.
---

# Memory Consolidation Skill

## When This Skill Activates

You will be invoked during the **memory consolidation sleep cycle** with a deterministically cleaned transcript (Pass 1 output). Your job is to perform **Pass 2 (LLM cleaning)**.

## Pass 2 Instructions

### Level: `min`
Entity normalization only:
- Resolve usernames, abbreviations, and references to consistent names
- Use the lookup table below for known entities
- For unknown entities, use context to infer the correct name
- If uncertain, keep the original text

### Level: `full` (default)
Everything in `min`, plus:
1. **Pronoun resolution** — replace ambiguous pronouns with concrete referents when clearly determinable
2. **Narrative collapsing** — merge retry sequences into clean single narratives (e.g., "tried X, failed, tried X again, succeeded" → "tried X, initially failed, then succeeded")
3. **Ambiguity preservation** — mark unclear spans with `[AMBIGUOUS: original text]`. **Never guess.**
4. **Leave original text as-is** for anything you're unsure about

### Entity Lookup Table
```json
{
  "chik_delight": "Rob",
  "clawdbot": "Agent"
}
```

## Output Format

The cleaned transcript MUST preserve the existing YAML frontmatter block (`---` ... `---`) exactly as-is. Only modify the body content below the frontmatter per the instructions above. For Fireflies meeting transcripts, add `pass2: true` to the frontmatter after cleaning to prevent re-processing.

## Sleep Cycle Architecture

The sleep cycle runs on three triggers:
1. **Context overflow** — when the model rejects the prompt
2. **Midnight EST** — nightly cron job
3. **Manual `/reset` or `/new`** — via `before_reset` hook

### Steps (in order):
1. **Pass 1 — Deterministic** (`before_reset` hook, blocking):
   - Session transcript cleansing via `transcript-cleaner.js`
   - Fireflies meeting transcript frontmattering via `cleanseFirefliesTranscripts`
2. **Pass 2 — Agentic** (consolidation turn in `commands-core.ts`, blocking):
   - LLM cleaning on cleansed session transcripts (this skill)
   - Episodic reflection writing
   - MEMORY.md semantic update
   - Fireflies meeting transcript Pass 2 cleaning
3. **Reset session** — clean slate

### Output Locations
| Document | Location | Type |
|---|---|---|
| Cleansed sessions | `memory/cleansed-sessions/YYYYMMDD_HHMMSS.md` | `type: session` |
| Episodic reflections | `memory/episodes/YYYYMMDD_HHMMSS.md` | `type: episode` |
| Semantic memory | `MEMORY.md` | append-only |
| Meeting transcripts | `memory/bpc_meetings/` | `type: meeting` |

### Key Principles
- **Clean, don't summarize** — preserve the full conversation, just remove noise
- **Significant tool outputs stay** — if the agent scraped, queried, or generated something, keep it
- **Ambiguous spans are marked, never guessed** — `[AMBIGUOUS: original text]`
- **Episodic reflections are autobiographical** — capture what happened, not just facts
- **MEMORY.md is append-only** — never overwrite existing entries

## Episodic Reflection Template

When writing episodic reflections, use this format:

```markdown
---
type: episode
session_id: <session_id>
cleansed_transcript: <matching_cleansed_filename>
date: YYYY-MM-DD
time_range: "HH:MM-HH:MM EST"
tags: [topic1, topic2]
outcome: success | partial | failure
salience: high | medium | low
trigger: user_request | scheduled_task | error_alert | context_overflow
---

## What Happened
[Narrative description of the session]

## What Succeeded
- [Key accomplishments]

## What Failed
- [What didn't work and why]

## What's Pending
- [ ] [Outstanding tasks]

## Key Decisions
- [Important choices made and rationale]

## Tools & Artifacts
- [What tools were used and what was produced]

## Context & Connections
[How this session relates to previous work]
```
