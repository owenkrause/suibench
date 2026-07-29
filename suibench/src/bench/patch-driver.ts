// The patch-mode driver — its own vertical (not a `bench` axis). Per entry: run
// the patch policy → overlay the model's sources → grade on real Docker via the
// PatchGraderBoundary → PatchGrade; roll up with passKPatch + aggregatePatchCorpus.
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
  CostMeter as CostMeterCtor,
  type CostMeter,
  type CostTotals,
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

/** Produces the model's patched sources for one entry (basename paths). */
export interface PatchPolicy {
  collectPatch(): Promise<MoveFile[]>;
}

export interface PatchDeps {
  /** Builds the patch policy for one entry's Observation (a factory, so pass@k
   *  re-runs get a fresh policy each attempt). */
  patchFor: (entry: DatasetEntry, observation: Observation, meter?: CostMeter) => PatchPolicy;
  manager: SandboxManager;
  image?: string;
  /** Max entries graded concurrently (default 1). pass@k stays sequential. */
  concurrency?: number;
  /** Called once per attempted entry with its accumulated cost. */
  onEntryCost?: (target: string, cost: CostTotals) => void;
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
): Promise<PatchRunScore> {
  const observation: Observation = {
    source: loadSource(entry),
    tools: patchTools(harness),
    env,
  };
  const patched = await deps.patchFor(entry, observation, meter).collectPatch();
  const vulnIds = entry.manifest.vulns.map((v) => v.id);
  if (patched.length === 0) return noPatch(entry, vulnIds);

  const patchedMount = overlayPatch(loadSource(entry), patched);
  const check = await loadCheck(entry);
  const boundary = makePatchGraderBoundary({
    entry,
    patchedMount,
    check,
    manager: deps.manager,
    image: deps.image,
  });
  return gradePatch(entry.target, vulnIds, boundary);
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
      if (entry.functionalPath) return true;
      console.error(`[patch] ${entry.target}: SKIPPED — no functional.ts (not patch-gradable)`);
      return false;
    });
  if (gradable.length === 0) {
    throw new Error("no patch-gradable entries matched (functional.ts required)");
  }

  const outcomes = await boundedMap(gradable, deps.concurrency ?? 1, async (entry): Promise<Outcome> => {
    const meter = new CostMeterCtor();
    try {
      try {
        const score = await passKPatch(k, entry.target, () =>
          patchEntryOnce(entry, env, harness, deps, meter),
        );
        return { ok: true, score };
      } catch (err) {
        if (!(err instanceof InfraError) && !(err instanceof AgentError)) throw err;
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
