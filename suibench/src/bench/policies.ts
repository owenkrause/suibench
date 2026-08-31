// Run factories for the bench driver. Both run the REAL agent (`runAgentLoop`)
// over a live `--network none` Sandbox on the sanitized mount, then parse what
// it left behind: `auditorRunFactory` is a `BenchDeps["runFor"]` (findings +
// exploits), `patchRunFactory` a `PatchDeps["patchFor"]` (corrected sources).
// Both need an API key + Docker.
import type {
  Observation,
  Exploit,
  Finding,
  MoveFile,
  Mount,
  Sandbox,
} from "core";
import {
  getModelClient,
  referenceLibrary,
  runAgentLoop,
  RefusalError,
  type EffortLevel,
  type CostMeter,
  type ModelClient,
  type AgentConversation,
  type StopKind,
  type CostTotals,
  type RefusalInfo,
} from "core/runtime";
import { buildAuditorPrompt } from "./prompt.js";
import type { DatasetEntry } from "../dataset/index.js";
import { parseReports, parsePatch } from "../adapters/parse.js";
import { waitForReady, readContextJson } from "../adapters/docker.js";

// A safety-classifier decline is not a zero-finding score. Turn the loop's
// terminal `refusal` into a RefusalError so the driver's per-entry isolation
// (same path as InfraError/AgentError) excludes it from the aggregate and flags
// it for rerun, rather than grading the empty sandbox as a miss.
function refusalDecline(refusal?: RefusalInfo): RefusalError {
  const detail = [
    refusal?.category ? `[${refusal.category}]` : undefined,
    refusal?.explanation ?? undefined,
  ]
    .filter(Boolean)
    .join(" ");
  return new RefusalError(
    `model declined the task${detail ? `: ${detail}` : ""}`,
    1,
    refusal?.category ?? null,
  );
}

// The prompt heading must not carry the entry's directory name — those names
// state their own bug class (e.g. `liquidation_seize_uncapped`) and leak the
// answer into the model-visible surface. The model addresses the package by its
// on-chain id, so a neutral heading loses nothing.
export const PROMPT_TARGET_LABEL = "target";

interface AuditSandbox extends Sandbox {
  readonly containerId: string;
}

export interface AuditSandboxManager {
  spawnAudit(mount: Mount): Promise<AuditSandbox>;
}

/** The real audit agent over a live sandbox. One container per run; the
 *  manager tears them all down on teardown/SIGINT. */
export interface AuditorFactoryOptions {
  manager: AuditSandboxManager;
  model: string;
  effort: EffortLevel;
  maxTurns?: number;
  /** Injectable so lifecycle/error paths are testable without credentials. */
  client?: ModelClient;
}

async function teardownQuietly(sandbox: AuditSandbox | undefined): Promise<void> {
  if (!sandbox) return;
  try {
    await sandbox.teardown();
  } catch {
    /* best-effort; the manager remains the final cleanup net */
  }
}

export function auditorRunFactory(opts: AuditorFactoryOptions) {
  const client = opts.client ?? getModelClient(opts.model);
  // The sandbox mounts ONLY the sanitized source the Observation carries.
  return async (
    observation: Observation,
    meter?: CostMeter,
  ): Promise<{
    exploits: Exploit[];
    findings: Finding[];
    conversation: AgentConversation;
    stopReason: StopKind;
    cost: CostTotals;
  }> => {
    let sandbox: AuditSandbox | undefined;
    try {
      sandbox = await opts.manager.spawnAudit(observation.source);
      const moveFiles = observation.source.files.filter((f) =>
        f.path.endsWith(".move"),
      );
      let systemPrompt: string;
      if (observation.tools.bash) {
        // Harnessed: the model gets a live localnet (loopback, published) in
        // its own container to build/deploy/test exploits against before
        // reporting — the localnet `entry` prompt + its packageId.
        await waitForReady(sandbox.containerId);
        const ctx = await readContextJson(sandbox.containerId);
        systemPrompt = buildAuditorPrompt({
          kind: "entry",
          entryName: PROMPT_TARGET_LABEL,
          moduleNames: moveFiles.map((f) => f.path),
          packageId: ctx.packageId,
        });
      } else {
        // Static: reason over inlined source, no execution.
        systemPrompt = buildAuditorPrompt({
          kind: "static-entry",
          entryName: PROMPT_TARGET_LABEL,
          modules: moveFiles.map((f) => ({
            name: f.path,
            source: f.contents,
          })),
        });
      }
      const result = await runAgentLoop({
        sandbox,
        client,
        systemPrompt,
        model: opts.model,
        effort: opts.effort,
        maxTurns: opts.maxTurns,
        enabledTools: observation.tools,
        references: referenceLibrary,
        meter,
      });
      if (result.stopReason === "refusal") throw refusalDecline(result.refusal);
      // The loop leaves findings.json + its exploit scripts in the sandbox; read
      // them out before the container goes away.
      const { exploits, findings } = await parseReports(sandbox);
      return {
        exploits,
        findings,
        conversation: result.conversation,
        stopReason: result.stopReason,
        cost: result.costs,
      };
    } finally {
      await teardownQuietly(sandbox);
    }
  };
}

/** The real patch agent: handed the known root causes, it returns corrected
 *  source. Harnessed → the localnet `patch` prompt with a live localnet to build/
 *  republish/test the fix before submitting; static → write it blind. Grading
 *  runs on real Docker either way. */
export function patchRunFactory(opts: AuditorFactoryOptions) {
  const client = opts.client ?? getModelClient(opts.model);
  return async (
    entry: DatasetEntry,
    observation: Observation,
    meter?: CostMeter,
  ): Promise<{
    sources: MoveFile[];
    conversation: AgentConversation;
    stopReason: StopKind;
    cost: CostTotals;
  }> => {
    let sandbox: AuditSandbox | undefined;
    try {
      sandbox = await opts.manager.spawnAudit(observation.source);
      const moveFiles = observation.source.files.filter((f) =>
        f.path.endsWith(".move"),
      );
      const rootCauses = entry.manifest.vulns.map((v) => v.root_cause);
      let systemPrompt: string;
      if (observation.tools.bash) {
        // Harnessed: live localnet — build/republish/test the fix first.
        await waitForReady(sandbox.containerId);
        const ctx = await readContextJson(sandbox.containerId);
        systemPrompt = buildAuditorPrompt({
          kind: "patch",
          entryName: PROMPT_TARGET_LABEL,
          moduleNames: moveFiles.map((f) => f.path),
          rootCauses,
          packageId: ctx.packageId,
        });
      } else {
        // Static: write the fix blind from inlined source.
        systemPrompt = buildAuditorPrompt({
          kind: "static-patch",
          entryName: PROMPT_TARGET_LABEL,
          modules: moveFiles.map((f) => ({
            name: f.path,
            source: f.contents,
          })),
          rootCauses,
        });
      }
      const result = await runAgentLoop({
        sandbox,
        client,
        systemPrompt,
        model: opts.model,
        effort: opts.effort,
        maxTurns: opts.maxTurns,
        enabledTools: observation.tools,
        references: referenceLibrary,
        meter,
      });
      if (result.stopReason === "refusal") throw refusalDecline(result.refusal);
      // The loop leaves patch.json + the rewritten sources in the sandbox; read
      // them out before the container goes away.
      const sources = await parsePatch(sandbox);
      return {
        sources,
        conversation: result.conversation,
        stopReason: result.stopReason,
        cost: result.costs,
      };
    } finally {
      await teardownQuietly(sandbox);
    }
  };
}
