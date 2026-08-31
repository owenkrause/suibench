// The patch-mode driver — its own vertical (not a `bench` axis). Per entry: run
// the patch agent → overlay the model's sources → grade on real Docker via the
// PatchGraderBoundary → PatchRunScore; roll up with passKPatch + aggregatePatchCorpus.
// Only entries with a `functional.ts` are patch-gradable. InfraError isolates to
// the entry (like `bench`), so one bad boot never voids the run.
import {
  gradePatch,
  passKPatch,
  aggregatePatchCorpus,
  sanitize,
  type PatchRunScore,
  type PatchEntryScore,
  type PatchCorpusScore,
  type PatchErroredEntry,
  type Mount,
  type MoveFile,
  type RunEnv,
  type Observation,
  type ToolMenu,
} from "core";
import {
  AgentError,
  RefusalError,
  CostMeter as CostMeterCtor,
  type AgentConversation,
  type CostMeter,
  type CostTotals,
  type StopKind,
  type TrajectorySink,
} from "core/runtime";
import {
  loadEntry,
  loadSource,
  loadCheck,
  type DatasetEntry,
} from "../dataset/index.js";
import { makePatchGraderBoundary } from "../adapters/patch-grader.js";
import { InfraError } from "../adapters/confirmer.js";
import type { SandboxManager } from "../adapters/sandbox.js";
import { boundedMap } from "../util/bounded.js";
import type { Harness } from "./driver.js";
import type { PatchTrajectory } from "./trajectory.js";

export interface PatchDeps {
  /** Runs the patch agent over one entry's Observation and returns its patched
   *  sources (basename paths) plus the loop's conversation/stopReason/cost.
   *  Called once per attempt, so pass@k re-runs get a fresh run each time. */
  patchFor: (
    entry: DatasetEntry,
    observation: Observation,
    meter?: CostMeter,
  ) => Promise<{
    sources: MoveFile[];
    conversation: AgentConversation;
    stopReason: StopKind;
    cost: CostTotals;
  }>;
  manager: SandboxManager;
  /** Max entries graded concurrently (default 1). pass@k stays sequential. */
  concurrency?: number;
  /** Called once per attempted entry with its accumulated cost. */
  onEntryCost?: (target: string, cost: CostTotals) => void;
  /** Persists one Trajectory per graded attempt. A save failure is logged and
   *  swallowed — it must never fail the run it's recording. */
  sink: TrajectorySink;
}

// Static patch: model writes the fix blind from inlined source + the known root
// cause. Harnessed patch: model gets bash + a live localnet to build/republish/
// test its fix before submitting. Grading runs on real Docker either way.
const patchTools = (harness: Harness): ToolMenu => ({
  bash: harness === "harnessed",
  writeFile: true,
  references: false,
});

const basenameOf = (p: string): string => p.split("/").pop() ?? p;

/** Overlay the model's patched sources onto the entry's, matching by basename
 *  (the model rewrites `vault.move`; the entry source is `sources/vault.move`). */
export function overlayPatch(base: Mount, patched: MoveFile[]): Mount {
  const fullByBasename = new Map(base.files.map((f) => [basenameOf(f.path), f.path]));
  const files = base.files.map((f) => ({ ...f }));
  const idxByPath = new Map(files.map((f, i) => [f.path, i]));
  for (const pf of patched) {
    const fullPath = fullByBasename.get(basenameOf(pf.path)) ?? pf.path;
    const idx = idxByPath.get(fullPath);
    const overlaid = { path: fullPath, contents: pf.contents };
    if (idx !== undefined) files[idx] = overlaid;
    else files.push(overlaid);
  }
  return sanitize(files);
}

function noPatch(entry: DatasetEntry, vulnIds: string[]): PatchRunScore {
  const err = "model produced no patch (no patch.json / empty patchedSources)";
  return {
    target: entry.target,
    compiles: false,
    functional_passes: false,
    patched: 0,
    total: vulnIds.length,
    perVuln: vulnIds.map((vulnId) => ({
      vulnId,
      exploit_still_succeeds: false,
      patch_correct: false,
      error: err,
    })),
    error: err,
  };
}

async function patchEntryOnce(
  entry: DatasetEntry,
  env: RunEnv,
  harness: Harness,
  deps: PatchDeps,
  meter?: CostMeter,
  attemptIndex = 0,
): Promise<PatchRunScore> {
  const observation: Observation = {
    source: loadSource(entry),
    tools: patchTools(harness),
    env,
  };
  const { sources, conversation, stopReason, cost } = await deps.patchFor(entry, observation, meter);
  const vulnIds = entry.manifest.vulns.map((v) => v.id);

  let score: PatchRunScore;
  if (sources.length === 0) {
    score = noPatch(entry, vulnIds);
  } else {
    const patchedMount = overlayPatch(loadSource(entry), sources);
    const check = await loadCheck(entry);
    const boundary = makePatchGraderBoundary({
      entry,
      patchedMount,
      check,
      manager: deps.manager,
    });
    score = await gradePatch(entry.target, vulnIds, boundary);
  }

  try {
    const trajectory: PatchTrajectory = {
      schemaVersion: 1,
      id: `${entry.target}-${attemptIndex}`,
      env,
      conversation,
      stopReason,
      cost,
      output: sources,
      score,
    };
    await deps.sink.save(trajectory);
  } catch (err) {
    console.error(
      `[patch] ${entry.target}: trajectory save failed — ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return score;
}

export async function benchPatch(
  entryDirs: string[],
  env: RunEnv,
  k: number,
  harness: Harness,
  deps: PatchDeps,
): Promise<PatchCorpusScore> {
  if (!Number.isSafeInteger(k) || k < 1) {
    throw new RangeError(`k must be a positive integer; got ${k}`);
  }
  type Outcome =
    | { ok: true; score: PatchEntryScore }
    | { ok: false; errored: PatchErroredEntry };

  const gradable = entryDirs
    .map(loadEntry)
    .filter((entry) => {
      if (!entry.functionalPath) {
        console.error(`[patch] ${entry.target}: SKIPPED — no functional.ts (not patch-gradable)`);
        return false;
      }
      // `loadCheck` throws for a detect-tier entry, and that throw escapes
      // boundedMap and rejects the whole corpus run. Skip loudly instead.
      if (entry.tier !== "confirmed") {
        console.error(`[patch] ${entry.target}: SKIPPED — detect-tier (no check.ts); ships functional.ts but is not patch-gradable`);
        return false;
      }
      return true;
    });
  if (gradable.length === 0) {
    throw new Error("no patch-gradable entries matched (functional.ts required)");
  }

  const outcomes = await boundedMap(gradable, deps.concurrency ?? 1, async (entry): Promise<Outcome> => {
    const meter = new CostMeterCtor();
    let attemptIndex = 0;
    try {
      try {
        const score = await passKPatch(k, entry.target, () =>
          patchEntryOnce(entry, env, harness, deps, meter, attemptIndex++),
        );
        return { ok: true, score };
      } catch (err) {
        if (
          !(err instanceof InfraError) &&
          !(err instanceof AgentError) &&
          !(err instanceof RefusalError)
        )
          throw err;
        console.error(`[patch] ${entry.target}: ERRORED — excluded from the rate, rerun to complete`);
        return {
          ok: false,
          errored: {
            target: entry.target,
            error: `${err.name}: ${err.message}`,
            attempts: err.attempts,
          },
        };
      }
    } finally {
      deps.onEntryCost?.(entry.target, meter.totals());
    }
  });

  const entries = outcomes.filter((o): o is { ok: true; score: PatchEntryScore } => o.ok).map((o) => o.score);
  const errored = outcomes.filter((o): o is { ok: false; errored: PatchErroredEntry } => !o.ok).map((o) => o.errored);
  return aggregatePatchCorpus(entries, errored);
}
