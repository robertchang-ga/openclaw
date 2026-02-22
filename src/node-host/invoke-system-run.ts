import crypto from "node:crypto";
import { resolveAgentConfig } from "../agents/agent-scope.js";
import { loadConfig } from "../config/config.js";
import type { GatewayClient } from "../gateway/client.js";
import {
  addAllowlistEntry,
  analyzeArgvCommand,
  evaluateExecAllowlist,
  evaluateShellAllowlist,
  isHostExecBinAllowed,
  recordAllowlistUse,
  resolveAllowAlwaysPatterns,
  resolveExecApprovals,
  type ExecAllowlistEntry,
  type ExecAsk,
  type ExecCommandSegment,
  type ExecSecurity,
} from "../infra/exec-approvals.js";
import type { ExecHostRequest, ExecHostResponse, ExecHostRunResult } from "../infra/exec-host.js";
import { resolveExecSafeBinRuntimePolicy } from "../infra/exec-safe-bin-runtime-policy.js";
import { sanitizeSystemRunEnvOverrides } from "../infra/host-env-security.js";
import { resolveSystemRunCommand } from "../infra/system-run-command.js";
import { evaluateSystemRunPolicy, resolveExecApprovalDecision } from "./exec-policy.js";
import type {
  ExecEventPayload,
  RunResult,
  SkillBinsProvider,
  SystemRunParams,
} from "./invoke-types.js";

type SystemRunInvokeResult = {
  ok: boolean;
  payloadJSON?: string | null;
  error?: { code?: string; message?: string } | null;
};
export { formatSystemRunAllowlistMissMessage } from "./exec-policy.js";

export async function handleSystemRunInvoke(opts: {
  client: GatewayClient;
  params: SystemRunParams;
  skillBins: SkillBinsProvider;
  execHostEnforced: boolean;
  execHostFallbackAllowed: boolean;
  resolveExecSecurity: (value?: string) => ExecSecurity;
  resolveExecAsk: (value?: string) => ExecAsk;
  isCmdExeInvocation: (argv: string[]) => boolean;
  sanitizeEnv: (overrides?: Record<string, string> | null) => Record<string, string> | undefined;
  runCommand: (
    argv: string[],
    cwd: string | undefined,
    env: Record<string, string> | undefined,
    timeoutMs: number | undefined,
  ) => Promise<RunResult>;
  runViaMacAppExecHost: (params: {
    approvals: ReturnType<typeof resolveExecApprovals>;
    request: ExecHostRequest;
  }) => Promise<ExecHostResponse | null>;
  sendNodeEvent: (client: GatewayClient, event: string, payload: unknown) => Promise<void>;
  buildExecEventPayload: (payload: ExecEventPayload) => ExecEventPayload;
  sendInvokeResult: (result: SystemRunInvokeResult) => Promise<void>;
  sendExecFinishedEvent: (params: {
    sessionKey: string;
    runId: string;
    cmdText: string;
    result: {
      stdout?: string;
      stderr?: string;
      error?: string | null;
      exitCode?: number | null;
      timedOut?: boolean;
      success?: boolean;
    };
  }) => Promise<void>;
}): Promise<void> {
  const command = resolveSystemRunCommand({
    command: opts.params.command,
    rawCommand: opts.params.rawCommand,
  });
  if (!command.ok) {
    await opts.sendInvokeResult({
      ok: false,
      error: { code: "INVALID_REQUEST", message: command.message },
    });
    return;
  }
  if (command.argv.length === 0) {
    await opts.sendInvokeResult({
      ok: false,
      error: { code: "INVALID_REQUEST", message: "command required" },
    });
    return;
  }

  const argv = command.argv;
  const rawCommand = command.rawCommand ?? "";
  const shellCommand = command.shellCommand;
  const cmdText = command.cmdText;
  const agentId = opts.params.agentId?.trim() || undefined;
  const cfg = loadConfig();
  const agentExec = agentId ? resolveAgentConfig(cfg, agentId)?.tools?.exec : undefined;
  const configuredSecurity = opts.resolveExecSecurity(
    agentExec?.security ?? cfg.tools?.exec?.security,
  );
  const configuredAsk = opts.resolveExecAsk(agentExec?.ask ?? cfg.tools?.exec?.ask);
  const approvals = resolveExecApprovals(agentId, {
    security: configuredSecurity,
    ask: configuredAsk,
  });
  const security = approvals.agent.security;
  const ask = approvals.agent.ask;
  const autoAllowSkills = approvals.agent.autoAllowSkills;
  const sessionKey = opts.params.sessionKey?.trim() || "node";
  const runId = opts.params.runId?.trim() || crypto.randomUUID();
  const approvalDecision = resolveExecApprovalDecision(opts.params.approvalDecision);
  const envOverrides = sanitizeSystemRunEnvOverrides({
    overrides: opts.params.env ?? undefined,
    shellWrapper: shellCommand !== null,
  });
  const env = opts.sanitizeEnv(envOverrides);
  const { safeBins, safeBinProfiles, trustedSafeBinDirs } = resolveExecSafeBinRuntimePolicy({
    global: cfg.tools?.exec,
    local: agentExec,
  });
  const bins = autoAllowSkills ? await opts.skillBins.current() : new Set<string>();
  let analysisOk = false;
  let allowlistMatches: ExecAllowlistEntry[] = [];
  let allowlistSatisfied = false;
  let segments: ExecCommandSegment[] = [];
  if (shellCommand) {
    const allowlistEval = evaluateShellAllowlist({
      command: shellCommand,
      allowlist: approvals.allowlist,
      safeBins,
      safeBinProfiles,
      cwd: opts.params.cwd ?? undefined,
      env,
      trustedSafeBinDirs,
      skillBins: bins,
      autoAllowSkills,
      platform: process.platform,
    });
    analysisOk = allowlistEval.analysisOk;
    allowlistMatches = allowlistEval.allowlistMatches;
    allowlistSatisfied =
      security === "allowlist" && analysisOk ? allowlistEval.allowlistSatisfied : false;
    segments = allowlistEval.segments;
  } else {
    const analysis = analyzeArgvCommand({ argv, cwd: opts.params.cwd ?? undefined, env });
    const allowlistEval = evaluateExecAllowlist({
      analysis,
      allowlist: approvals.allowlist,
      safeBins,
      safeBinProfiles,
      cwd: opts.params.cwd ?? undefined,
      trustedSafeBinDirs,
      skillBins: bins,
      autoAllowSkills,
    });
    analysisOk = analysis.ok;
    allowlistMatches = allowlistEval.allowlistMatches;
    allowlistSatisfied =
      security === "allowlist" && analysisOk ? allowlistEval.allowlistSatisfied : false;
    segments = analysis.segments;
  }
  const isWindows = process.platform === "win32";
  const cmdInvocation = shellCommand
    ? opts.isCmdExeInvocation(segments[0]?.argv ?? [])
    : opts.isCmdExeInvocation(argv);

  // hostExecBins: commands whose binary is in the hostExecBins list are pre-authorized
  // by the user. Skip the approval flow for simple commands only.
  // We require segments.length === 1 (no pipes or chaining) to prevent shell injection
  // via e.g. `mcporter ; cat /etc/passwd`. Chained/piped commands produce multiple segments
  // and are handled by the normal allowlist/approval flow instead.
  let hostExecBinsOverride = false;
  let hostExecBinsDenied = false;
  let hostExecBinsDeniedReason = "";
  if (approvals.hostExecBins.size > 0 && analysisOk && segments.length === 1) {
    const binToken = segments[0]?.resolution?.executableName?.toLowerCase() || "";
    const binRule = binToken ? approvals.hostExecBins.get(binToken) : undefined;
    if (binRule) {
      if (isHostExecBinAllowed(binRule, segments[0]?.argv ?? [])) {
        hostExecBinsOverride = true;
        await opts.sendNodeEvent(
          opts.client,
          "exec.hostExecBins",
          opts.buildExecEventPayload({
            sessionKey,
            runId,
            host: "node",
            command: cmdText,
            reason: `hostExecBins:${binToken}`,
          }),
        );
      } else {
        // Binary matches but subcommand is denied — hard deny regardless of
        // which tool sent the command (exec or nodes run). This prevents a
        // denied subcommand from falling through to the general allowlist.
        hostExecBinsDenied = true;
        hostExecBinsDeniedReason = `hostExecBins:${binToken}:subcommand-denied`;
      }
    }
  }

  if (security === "allowlist" && isWindows && cmdInvocation) {
    analysisOk = false;
    allowlistSatisfied = false;
  }

  // ── Hard deny: hostExecBins subcommand denied ──────────────────────────────
  // If the binary matches a hostExecBins entry but the subcommand is denied,
  // block immediately. This is a universal gate — it fires regardless of which
  // tool sent the command (exec, nodes run, etc.) and cannot be overridden by
  // the general allowlist or approval flow.
  if (hostExecBinsDenied) {
    await opts.sendNodeEvent(
      opts.client,
      "exec.denied",
      opts.buildExecEventPayload({
        sessionKey,
        runId,
        host: "node",
        command: cmdText,
        reason: hostExecBinsDeniedReason,
      }),
    );
    await opts.sendInvokeResult({
      ok: false,
      error: {
        code: "UNAVAILABLE",
        message: `SYSTEM_RUN_DENIED: ${hostExecBinsDeniedReason}`,
      },
    });
    return;
  }

  // hostExecBinsOverride bypasses security=deny and approval requirements
  if (security === "deny" && hostExecBinsOverride) {
    // Allow — hostExecBins are explicitly trusted by the user.
  }

  const useMacAppExec = process.platform === "darwin";
  if (useMacAppExec) {
    const execRequest: ExecHostRequest = {
      command: argv,
      rawCommand: rawCommand || shellCommand || null,
      cwd: opts.params.cwd ?? null,
      env: envOverrides ?? null,
      timeoutMs: opts.params.timeoutMs ?? null,
      needsScreenRecording: opts.params.needsScreenRecording ?? null,
      agentId: agentId ?? null,
      sessionKey: sessionKey ?? null,
      approvalDecision,
    };
    const response = await opts.runViaMacAppExecHost({ approvals, request: execRequest });
    if (!response) {
      if (opts.execHostEnforced || !opts.execHostFallbackAllowed) {
        await opts.sendNodeEvent(
          opts.client,
          "exec.denied",
          opts.buildExecEventPayload({
            sessionKey,
            runId,
            host: "node",
            command: cmdText,
            reason: "companion-unavailable",
          }),
        );
        await opts.sendInvokeResult({
          ok: false,
          error: {
            code: "UNAVAILABLE",
            message: "COMPANION_APP_UNAVAILABLE: macOS app exec host unreachable",
          },
        });
        return;
      }
    } else if (!response.ok) {
      const reason = response.error.reason ?? "approval-required";
      await opts.sendNodeEvent(
        opts.client,
        "exec.denied",
        opts.buildExecEventPayload({
          sessionKey,
          runId,
          host: "node",
          command: cmdText,
          reason,
        }),
      );
      await opts.sendInvokeResult({
        ok: false,
        error: { code: "UNAVAILABLE", message: response.error.message },
      });
      return;
    } else {
      const result: ExecHostRunResult = response.payload;
      await opts.sendExecFinishedEvent({ sessionKey, runId, cmdText, result });
      await opts.sendInvokeResult({
        ok: true,
        payloadJSON: JSON.stringify(result),
      });
      return;
    }
  }

  const policy = evaluateSystemRunPolicy({
    security: hostExecBinsOverride ? "full" : security,
    ask: hostExecBinsOverride ? "off" : ask,
    analysisOk,
    allowlistSatisfied,
    approvalDecision,
    approved: opts.params.approved === true,
    isWindows,
    cmdInvocation,
  });
  analysisOk = policy.analysisOk;
  allowlistSatisfied = policy.allowlistSatisfied;
  if (!policy.allowed) {
    await opts.sendNodeEvent(
      opts.client,
      "exec.denied",
      opts.buildExecEventPayload({
        sessionKey,
        runId,
        host: "node",
        command: cmdText,
        reason: policy.eventReason,
      }),
    );
    await opts.sendInvokeResult({
      ok: false,
      error: { code: "UNAVAILABLE", message: policy.errorMessage },
    });
    return;
  }

  if (policy.approvalDecision === "allow-always" && security === "allowlist") {
    if (policy.analysisOk) {
      const patterns = resolveAllowAlwaysPatterns({
        segments,
        cwd: opts.params.cwd ?? undefined,
        env,
        platform: process.platform,
      });
      for (const pattern of patterns) {
        if (pattern) {
          addAllowlistEntry(approvals.file, agentId, pattern);
        }
      }
    }
  }

  if (allowlistMatches.length > 0) {
    const seen = new Set<string>();
    for (const match of allowlistMatches) {
      if (!match?.pattern || seen.has(match.pattern)) {
        continue;
      }
      seen.add(match.pattern);
      recordAllowlistUse(
        approvals.file,
        agentId,
        match,
        cmdText,
        segments[0]?.resolution?.resolvedPath,
      );
    }
  }

  if (opts.params.needsScreenRecording === true) {
    await opts.sendNodeEvent(
      opts.client,
      "exec.denied",
      opts.buildExecEventPayload({
        sessionKey,
        runId,
        host: "node",
        command: cmdText,
        reason: "permission:screenRecording",
      }),
    );
    await opts.sendInvokeResult({
      ok: false,
      error: { code: "UNAVAILABLE", message: "PERMISSION_MISSING: screenRecording" },
    });
    return;
  }

  let execArgv = argv;
  if (
    security === "allowlist" &&
    isWindows &&
    !policy.approvedByAsk &&
    shellCommand &&
    policy.analysisOk &&
    policy.allowlistSatisfied &&
    segments.length === 1 &&
    segments[0]?.argv.length > 0
  ) {
    execArgv = segments[0].argv;
  }

  const result = await opts.runCommand(
    execArgv,
    opts.params.cwd?.trim() || undefined,
    env,
    opts.params.timeoutMs ?? undefined,
  );
  if (result.truncated) {
    const suffix = "... (truncated)";
    if (result.stderr.trim().length > 0) {
      result.stderr = `${result.stderr}\n${suffix}`;
    } else {
      result.stdout = `${result.stdout}\n${suffix}`;
    }
  }
  await opts.sendExecFinishedEvent({ sessionKey, runId, cmdText, result });

  await opts.sendInvokeResult({
    ok: true,
    payloadJSON: JSON.stringify({
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      success: result.success,
      stdout: result.stdout,
      stderr: result.stderr,
      error: result.error ?? null,
    }),
  });
}
