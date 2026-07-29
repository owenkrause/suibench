// Policy factories for the bench driver. Each returns a `BenchDeps["policyFor"]`
// — a per-entry factory that wraps that entry's Observation into a `Policy`.
//
//  - auditorPolicyFactory: the REAL agent (AuditorPolicy) over a live `--network
//    none` Sandbox on the sanitized mount. Needs an API key + Docker.
//  - scriptedPolicyFactory: replays a fixed report per entry (no model, no
//    Docker) — the driver-runnable-without-a-model path.
//  - replayPolicyFactory: replays a recorded trajectory per entry.
import type {
  Policy,
  Observation,
  Action,
  Trajectory,
  MoveFile,
  Mount,
  Sandbox,
} from "core";
import type { PatchPolicy } from "./patch-driver.js";
import {
  AuditorPolicy,
  ScriptedPolicy,
  ReplayPolicy,
  buildAuditorPrompt,
  getModelClient,
  referenceLibrary,
  type EffortLevel,
  type CostMeter,
  type ModelClient,
} from "core/runtime";
import type { DatasetEntry } from "../dataset/index.js";
import { waitForReady, readContextJson } from "../adapters/sandbox.js";

interface AuditSandbox extends Sandbox {
  readonly containerId: string;
}

export interface AuditSandboxManager {
  spawnAudit(mount: Mount): Promise<AuditSandbox>;
}

/** The real audit agent over a live sandbox. One container per entry; the
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

export function auditorPolicyFactory(opts: AuditorFactoryOptions) {
  const client = opts.client ?? getModelClient(opts.model);
  return (entry: DatasetEntry, observation: Observation, meter?: CostMeter): Policy => {
    // Lazy: AuditorPolicy's first act() runs the loop; we boot the sandbox then.
    // The sandbox mounts ONLY the sanitized source the Observation carries.
    let policy: AuditorPolicy | null = null;
    let initialized = false;
    return {
      async act(o: Observation): Promise<Action> {
        if (initialized) return policy!.act(o);
        initialized = true;
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
            // reporting — the devnet `entry` prompt + its packageId.
            await waitForReady(sandbox.containerId);
            const ctx = await readContextJson(sandbox.containerId);
            systemPrompt = buildAuditorPrompt({
              kind: "entry",
              entryName: entry.target,
              moduleNames: moveFiles.map((f) => f.path),
              packageId: ctx.packageId,
              rpcUrl: "http://127.0.0.1:9000",
              network: "devnet",
            });
          } else {
            // Static: reason over inlined source, no execution.
            systemPrompt = buildAuditorPrompt({
              kind: "static-entry",
              entryName: entry.target,
              modules: moveFiles.map((f) => ({
                name: f.path,
                source: f.contents,
              })),
            });
          }
          policy = new AuditorPolicy({
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
          // The first act runs the full agent loop and buffers every report. The
          // sandbox is no longer needed once that call returns.
          return await policy.act(o);
        } finally {
          await teardownQuietly(sandbox);
        }
      },
    };
  };
}

/** The real patch agent: handed the known root causes, it returns corrected
 *  source. Harnessed → the devnet `patch` prompt with a live localnet to build/
 *  republish/test the fix before submitting; static → write it blind. Grading
 *  runs on real Docker either way. Exposes `collectPatch` for the patch driver. */
export function patchPolicyFactory(opts: AuditorFactoryOptions) {
  const client = opts.client ?? getModelClient(opts.model);
  return (entry: DatasetEntry, observation: Observation, meter?: CostMeter): PatchPolicy => {
    let collected: Promise<MoveFile[]> | null = null;
    return {
      collectPatch() {
        if (!collected) {
          collected = (async () => {
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
                  entryName: entry.target,
                  moduleNames: moveFiles.map((f) => f.path),
                  rootCauses,
                  packageId: ctx.packageId,
                  rpcUrl: "http://127.0.0.1:9000",
                });
              } else {
                // Static: write the fix blind from inlined source.
                systemPrompt = buildAuditorPrompt({
                  kind: "static-patch",
                  entryName: entry.target,
                  modules: moveFiles.map((f) => ({
                    name: f.path,
                    source: f.contents,
                  })),
                  rootCauses,
                });
              }
              const policy = new AuditorPolicy({
                sandbox,
                client,
                systemPrompt,
                model: opts.model,
                effort: opts.effort,
                maxTurns: opts.maxTurns,
                enabledTools: observation.tools,
                meter,
              });
              return await policy.collectPatch(observation);
            } finally {
              await teardownQuietly(sandbox);
            }
          })();
        }
        return collected;
      },
    };
  };
}

/** A fixed set of reports per entry (keyed by target), else a null policy. */
export function scriptedPolicyFactory(
  byTarget: Record<string, Action[]>,
) {
  return (entry: DatasetEntry): Policy =>
    new ScriptedPolicy(byTarget[entry.target] ?? []);
}

/** Replay a recorded trajectory per entry (keyed by target). */
export function replayPolicyFactory(
  byTarget: Record<string, Trajectory>,
) {
  return (entry: DatasetEntry): Policy => {
    const t = byTarget[entry.target];
    return t ? new ReplayPolicy(t) : new ScriptedPolicy([]);
  };
}
