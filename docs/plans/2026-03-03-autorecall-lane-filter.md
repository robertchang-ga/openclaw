# autoRecall Lane Filter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stop `autoRecall` from injecting memories into heartbeat and cron-delivery runs by threading a `lane` field from run origin through to plugin hook context.

**Architecture:** Add `lane?: string` to `PluginHookAgentContext` (the struct passed to every plugin hook). Thread it from `RunEmbeddedPiAgentParams.lane` (already exists) down to `hookCtx` in `run.ts` and `attempt.ts`. For the heartbeat path (which goes via `GetReplyOptions`), add `lane` there and forward it into `runEmbeddedPiAgent`. For the cron delivery path (which goes via `callGateway`), add `lane: "cron"` in the announce functions. Update both cognee and lancedb plugins to filter on `ctx.lane` instead of session-key string matching.

**Tech Stack:** TypeScript (ESM), Vitest, no new dependencies.

---

### Task 1: Add `lane` to `PluginHookAgentContext`

**Files:**

- Modify: `src/plugins/types.ts:326-332`

**Step 1: Write the failing test**

In `src/agents/pi-embedded-runner/run/attempt.test.ts`, find the existing `before_agent_start` test and add a new test after it:

```typescript
it("passes lane from params into hookCtx", async () => {
  const capturedCtx: PluginHookAgentContext[] = [];
  const params = makeAttemptParams({ lane: "heartbeat" } as Partial<EmbeddedRunAttemptParams>);
  // ... existing test harness setup ...
  // Verify capturedCtx[0].lane === "heartbeat"
  expect(capturedCtx[0]?.lane).toBe("heartbeat");
});
```

(This test shape is illustrative — adapt to the existing test fixture in the file. The key assertion is `ctx.lane === "heartbeat"`.)

**Step 2: Run test to verify it fails**

```bash
pnpm test src/agents/pi-embedded-runner/run/attempt.test.ts --reporter=verbose
```

Expected: FAIL — `lane` property doesn't exist on `PluginHookAgentContext`.

**Step 3: Add `lane` to the type**

In `src/plugins/types.ts` at line 326:

```typescript
export type PluginHookAgentContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  workspaceDir?: string;
  messageProvider?: string;
  /** Run lane (e.g. "heartbeat", "cron"). Undefined for normal user-facing runs. */
  lane?: string;
};
```

**Step 4: Run test to confirm it still fails (lane not yet wired)**

```bash
pnpm test src/agents/pi-embedded-runner/run/attempt.test.ts --reporter=verbose
```

Expected: FAIL — `lane` is undefined (not yet passed through).

**Step 5: Commit type addition only**

```bash
scripts/committer "feat(plugins): add lane field to PluginHookAgentContext" src/plugins/types.ts
```

---

### Task 2: Thread `lane` through `RunEmbeddedPiAgentParams` → `hookCtx` in main run path

**Files:**

- Modify: `src/agents/pi-embedded-runner/run/types.ts:11-14`
- Modify: `src/agents/pi-embedded-runner/run.ts:249-255` and `src/agents/pi-embedded-runner/run.ts:575-625`

**Background:**

- `RunEmbeddedPiAgentParams` already has `lane?: string` (in `run/params.ts:99`).
- `EmbeddedRunAttemptBase` (the base for `EmbeddedRunAttemptParams`) currently `Omit`s `lane` from `RunEmbeddedPiAgentParams` (see `run/types.ts:13`).
- Two `hookCtx` objects are built in `run.ts` (line ~249) and `attempt.ts` (line ~1041); neither includes `lane`.

**Step 1: Remove `lane` from `Omit` in `run/types.ts`**

In `src/agents/pi-embedded-runner/run/types.ts` line 11-14, change:

```typescript
type EmbeddedRunAttemptBase = Omit<
  RunEmbeddedPiAgentParams,
  "provider" | "model" | "authProfileId" | "authProfileIdSource" | "thinkLevel" | "lane" | "enqueue"
>;
```

to:

```typescript
type EmbeddedRunAttemptBase = Omit<
  RunEmbeddedPiAgentParams,
  "provider" | "model" | "authProfileId" | "authProfileIdSource" | "thinkLevel" | "enqueue"
>;
```

**Step 2: Add `lane` to `hookCtx` in `run.ts` (model-resolve path, line ~249)**

```typescript
const hookCtx = {
  agentId: workspaceResolution.agentId,
  sessionKey: params.sessionKey,
  sessionId: params.sessionId,
  workspaceDir: resolvedWorkspace,
  messageProvider: params.messageProvider ?? undefined,
  lane: params.lane,
};
```

**Step 3: Pass `lane` to `runEmbeddedAttempt` in `run.ts` (line ~575)**

In the `runEmbeddedAttempt({...})` call, add:

```typescript
lane: params.lane,
```

(This now type-checks because `lane` is no longer Omit-ted from `EmbeddedRunAttemptBase`.)

**Step 4: Add `lane` to `hookCtx` in `attempt.ts` (line ~1041)**

```typescript
const hookCtx = {
  agentId: hookAgentId,
  sessionKey: params.sessionKey,
  sessionId: params.sessionId,
  workspaceDir: params.workspaceDir,
  messageProvider: params.messageProvider ?? undefined,
  lane: params.lane,
};
```

**Step 5: Run type-check**

```bash
pnpm tsgo
```

Expected: no errors.

**Step 6: Run tests**

```bash
pnpm test src/agents/pi-embedded-runner --reporter=verbose
```

Expected: existing tests pass.

**Step 7: Commit**

```bash
scripts/committer "feat(embedded): thread lane into PluginHookAgentContext hookCtx" \
  src/agents/pi-embedded-runner/run/types.ts \
  src/agents/pi-embedded-runner/run.ts \
  src/agents/pi-embedded-runner/run/attempt.ts
```

---

### Task 3: Thread `lane` through `GetReplyOptions` → `runEmbeddedPiAgent` (normal reply path)

**Files:**

- Modify: `src/auto-reply/types.ts:16-50`
- Modify: `src/auto-reply/reply/agent-runner-execution.ts` (the `runEmbeddedPiAgent` call, line ~286)

**Background:**

- Heartbeat runs go through `getReplyFromConfig` → `agent-runner.ts` → `runAgentTurnWithFallback` → `runEmbeddedPiAgent`.
- `runAgentTurnWithFallback` already receives `opts?: GetReplyOptions`, so once `GetReplyOptions` has `lane`, it's available at the call site as `params.opts?.lane`.

**Step 1: Add `lane` to `GetReplyOptions`**

In `src/auto-reply/types.ts` after `isHeartbeat?: boolean` (line 29):

```typescript
/** Run lane for plugin filtering (e.g. "heartbeat", "cron"). Undefined for normal runs. */
lane?: string;
```

**Step 2: Add `lane` to the `runEmbeddedPiAgent` call in `agent-runner-execution.ts`**

In the `runEmbeddedPiAgent({...})` call (around line 286), add:

```typescript
lane: params.opts?.lane,
```

**Step 3: Run type-check**

```bash
pnpm tsgo
```

Expected: no errors.

**Step 4: Run tests**

```bash
pnpm test src/auto-reply --reporter=verbose
```

Expected: existing tests pass.

**Step 5: Commit**

```bash
scripts/committer "feat(reply): thread lane from GetReplyOptions into runEmbeddedPiAgent" \
  src/auto-reply/types.ts \
  src/auto-reply/reply/agent-runner-execution.ts
```

---

### Task 4: Pass `lane: "heartbeat"` from heartbeat runner

**Files:**

- Modify: `src/infra/heartbeat-runner.ts:741-742`

**Background:**
`heartbeat-runner.ts` calls `getReplyFromConfig(ctx, { isHeartbeat: true, ... }, cfg)`. After Task 3, this now needs `lane: "heartbeat"` too.

**Step 1: Locate the call site**

In `src/infra/heartbeat-runner.ts` around line 741:

```typescript
? { isHeartbeat: true, heartbeatModelOverride, suppressToolErrorWarnings }
: { isHeartbeat: true, suppressToolErrorWarnings };
```

**Step 2: Add `lane: "heartbeat"`**

```typescript
? { isHeartbeat: true, lane: "heartbeat", heartbeatModelOverride, suppressToolErrorWarnings }
: { isHeartbeat: true, lane: "heartbeat", suppressToolErrorWarnings };
```

**Step 3: Run tests**

```bash
pnpm test src/infra/heartbeat-runner --reporter=verbose
```

Expected: existing tests pass (they assert `isHeartbeat: true` via `expect.objectContaining` so the extra `lane` field is fine).

**Step 4: Run type-check**

```bash
pnpm tsgo
```

**Step 5: Commit**

```bash
scripts/committer "feat(heartbeat): pass lane: heartbeat to getReplyFromConfig" \
  src/infra/heartbeat-runner.ts
```

---

### Task 5: Thread `lane: "cron"` through cron delivery announce path

**Files:**

- Modify: `src/agents/subagent-announce-queue.ts:21-31`
- Modify: `src/agents/subagent-announce.ts` (4 functions)
- Modify: `src/cron/isolated-agent/delivery-dispatch.ts:291-315`

**Background:**
The cron delivery announce fires `callGateway({ method: "agent", params: { ... } })`. The gateway `agent` handler (confirmed at `src/gateway/server-methods/agent.ts:191,608`) already reads `lane` from params and passes it to `runEmbeddedPiAgent`. So adding `lane: "cron"` to the `callGateway` params is sufficient.

The announce can go via two paths: **direct** (`sendSubagentAnnounceDirectly`) or **queued** (`sendAnnounce` via `AnnounceQueueItem`). Both need updating.

**Step 1: Add `lane` to `AnnounceQueueItem`**

In `src/agents/subagent-announce-queue.ts` line 21-31:

```typescript
export type AnnounceQueueItem = {
  announceId?: string;
  prompt: string;
  summaryLine?: string;
  enqueuedAt: number;
  sessionKey: string;
  origin?: DeliveryContext;
  originKey?: string;
  lane?: string;
};
```

**Step 2: Pass `lane` through `sendAnnounce` (queued path, line ~589-601)**

In `sendAnnounce(item: AnnounceQueueItem)`, add `lane: item.lane` to the `callGateway` params:

```typescript
await callGateway({
  method: "agent",
  params: {
    sessionKey: item.sessionKey,
    message: item.prompt,
    channel: requesterIsSubagent ? undefined : origin?.channel,
    accountId: requesterIsSubagent ? undefined : origin?.accountId,
    to: requesterIsSubagent ? undefined : origin?.to,
    threadId: requesterIsSubagent ? undefined : threadId,
    deliver: !requesterIsSubagent,
    idempotencyKey,
    lane: item.lane,
  },
  timeoutMs: announceTimeoutMs,
});
```

**Step 3: Pass `lane` to `enqueueAnnounce` in `maybeQueueSubagentAnnounce` (line ~645)**

Add `lane?: string` to `maybeQueueSubagentAnnounce` params, then pass it in `enqueueAnnounce`:

```typescript
async function maybeQueueSubagentAnnounce(params: {
  requesterSessionKey: string;
  announceId?: string;
  triggerMessage: string;
  summaryLine?: string;
  requesterOrigin?: DeliveryContext;
  signal?: AbortSignal;
  lane?: string;
```

And in the `enqueueAnnounce` call inside `maybeQueueSubagentAnnounce`:

```typescript
enqueueAnnounce({
  key: buildAnnounceQueueKey(canonicalKey, origin),
  item: {
    announceId: params.announceId,
    prompt: params.triggerMessage,
    summaryLine: params.summaryLine,
    enqueuedAt: Date.now(),
    sessionKey: canonicalKey,
    origin,
    lane: params.lane,
  },
  settings: queueSettings,
  send: sendAnnounce,
});
```

**Step 4: Add `lane` to `sendSubagentAnnounceDirectly` params (line ~704)**

```typescript
async function sendSubagentAnnounceDirectly(params: {
  targetRequesterSessionKey: string;
  triggerMessage: string;
  completionMessage?: string;
  expectsCompletionMessage: boolean;
  bestEffortDeliver?: boolean;
  completionRouteMode?: "bound" | "fallback" | "hook";
  spawnMode?: SpawnSubagentMode;
  directIdempotencyKey: string;
  completionDirectOrigin?: DeliveryContext;
  directOrigin?: DeliveryContext;
  requesterIsSubagent: boolean;
  signal?: AbortSignal;
  lane?: string;
```

In the two `callGateway` calls inside this function (line ~835 and ~589), add `lane: params.lane` to the `params` object.

**Step 5: Thread `lane` through `deliverSubagentAnnouncement` (line ~865)**

Add `lane?: string` to params, then pass it to both `maybeQueueSubagentAnnounce` and `sendSubagentAnnounceDirectly`:

```typescript
async function deliverSubagentAnnouncement(params: {
  // ... existing fields ...
  lane?: string;
```

In the body:

```typescript
queue: async () =>
  await maybeQueueSubagentAnnounce({
    // ... existing ...
    lane: params.lane,
  }),
direct: async () =>
  await sendSubagentAnnounceDirectly({
    // ... existing ...
    lane: params.lane,
  }),
```

**Step 6: Thread `lane` through `runSubagentAnnounceFlow` (line ~1039)**

Add `lane?: string` to `runSubagentAnnounceFlow` params, thread it to `deliverSubagentAnnouncement`:

```typescript
export async function runSubagentAnnounceFlow(params: {
  // ... existing fields ...
  lane?: string;
```

Find the `deliverSubagentAnnouncement` call(s) inside and add `lane: params.lane`.

**Step 7: Pass `lane: "cron"` in `delivery-dispatch.ts`**

In `src/cron/isolated-agent/delivery-dispatch.ts` around line 291:

```typescript
const didAnnounce = await runSubagentAnnounceFlow({
  childSessionKey: params.agentSessionKey,
  // ... existing fields ...
  lane: "cron",
});
```

**Step 8: Run type-check**

```bash
pnpm tsgo
```

Expected: no errors.

**Step 9: Run tests**

```bash
pnpm test src/agents/subagent-announce src/cron/isolated-agent --reporter=verbose
```

Expected: existing tests pass.

**Step 10: Commit**

```bash
scripts/committer "feat(cron): thread lane: cron through announce path to callGateway" \
  src/agents/subagent-announce-queue.ts \
  src/agents/subagent-announce.ts \
  src/cron/isolated-agent/delivery-dispatch.ts
```

---

### Task 6: Update cognee plugin to filter on `ctx.lane`

**Files:**

- Modify: `cognee-plugin-source.js:988-1004`

**Background:**
The current filter uses brittle session-key string matching. Heartbeat session keys (e.g. `agent:main:main`) do NOT contain "heartbeat", so the filter is broken. After Task 2-5, `ctx.lane` will reliably be `"heartbeat"` or `"cron"` for automated runs, and `undefined` for normal user-facing runs.

**Step 1: Replace the session-key filter**

Change (line ~995-1004):

```javascript
const sk = ctx.sessionKey ?? "";
if (
  sk.includes("heartbeat") ||
  sk.includes("cron") ||
  sk.includes("exec-event") ||
  sk.includes("discord:channel:1475851746550087775")
) {
  api.logger.debug?.(`memory-cognee: skipping recall (internal/voice: ${sk})`);
  return;
}
```

to:

```javascript
if (ctx.lane === "heartbeat" || ctx.lane === "cron") {
  api.logger.debug?.(`memory-cognee: skipping recall (internal run, lane=${ctx.lane})`);
  return;
}
const sk = ctx.sessionKey ?? "";
if (sk.includes("exec-event") || sk.includes("discord:channel:1475851746550087775")) {
  api.logger.debug?.(`memory-cognee: skipping recall (internal/voice: ${sk})`);
  return;
}
```

(Keep the session-key fallbacks for `exec-event` and the hard-coded channel ID — these don't have a lane yet and shouldn't regress.)

**Step 2: Run type-check**

```bash
pnpm tsgo
```

No TypeScript in this JS file; just confirm no syntax errors:

```bash
node --input-type=module < cognee-plugin-source.js 2>&1 | head -5
```

Actually, just run the tests and trust the change is trivially correct.

**Step 3: Run tests**

```bash
pnpm test --reporter=verbose 2>&1 | tail -20
```

**Step 4: Commit**

```bash
scripts/committer "fix(cognee): filter autoRecall on ctx.lane instead of session-key string matching" \
  cognee-plugin-source.js
```

---

### Task 7: Add lane filter to lancedb autoRecall

**Files:**

- Modify: `extensions/memory-lancedb/index.ts:538-555`

**Background:**
The lancedb `before_agent_start` handler has NO lane filtering at all — only a `prompt.length < 5` guard.

**Step 1: Add lane guard at top of handler**

In `src/extensions/memory-lancedb/index.ts` (or wherever the file is — confirm path first with `find`), change:

```typescript
api.on("before_agent_start", async (event) => {
  if (!event.prompt || event.prompt.length < 5) {
    return;
  }
```

to:

```typescript
api.on("before_agent_start", async (event, ctx) => {
  if (ctx.lane === "heartbeat" || ctx.lane === "cron") {
    return;
  }
  if (!event.prompt || event.prompt.length < 5) {
    return;
  }
```

**Step 2: Run type-check**

```bash
pnpm tsgo
```

**Step 3: Run tests**

```bash
pnpm test extensions/memory-lancedb --reporter=verbose
```

**Step 4: Commit**

```bash
scripts/committer "fix(lancedb): skip autoRecall for heartbeat and cron lanes" \
  extensions/memory-lancedb/index.ts
```

---

### Task 8: Run full test suite + typecheck

**Step 1: Full type-check**

```bash
pnpm tsgo
```

Expected: no errors.

**Step 2: Full test run**

```bash
OPENCLAW_TEST_PROFILE=low OPENCLAW_TEST_SERIAL_GATEWAY=1 pnpm test
```

Expected: all tests pass (or pre-existing failures only).

**Step 3: Commit if any formatting-only diffs remain**

```bash
pnpm check
pnpm format:fix
scripts/committer "chore: fix formatting" <changed files>
```
