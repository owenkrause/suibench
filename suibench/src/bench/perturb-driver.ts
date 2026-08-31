// --perturb mode: for each confirmed-tier entry, score the original once, regenerate
// K twins from derived seeds, materialize each into `<dump>/<target>__<i>/`, score each
// through the SAME benchEntry pipeline, and compute the perturbation gap. Twins are the
// dumped artifacts — grading and auditability are the same files. No committed twins.
//
// Separator is `__`, not `#`: `#` in a dir name is parsed as a URL fragment by
// dynamic `import()` (used by `loadCheck` for confirmed-tier entries), silently
// truncating the path — reproduces in plain Node for a bare path, and even after
// routing through `pathToFileURL` still breaks under vite-node's import
// interception (Vitest). `__` sidesteps the hazard entirely.
//
// The original is scored from a COMMENT-STRIPPED materialization (`stripEntry`, no
// rename), not the raw entry dir: `generateTwin` already strips the twin's comments,
// so scoring the raw (commented) original would confound the gap with a
// comment-information-loss signal instead of isolating rename robustness.
import { join } from "node:path";
import { mkdirSync } from "node:fs";
import type { ErroredEntry } from "core";
import { AgentError, RefusalError, CostMeter as CostMeterCtor } from "core/runtime";
import type { RunConfig, BenchDeps } from "./driver.js";
import { benchEntry } from "./driver.js";
import { InfraError } from "../adapters/confirmer.js";
import { loadEntry } from "../dataset/index.js";
import { readEntryFiles, writeTwinDir, twinSeed } from "./materialize.js";
import { generateTwin, stripEntry } from "../perturbation/transform.js";
import { perturbationGap, type PerturbationResult, type PerturbationReport } from "./report.js";
import { boundedMap } from "../util/bounded.js";

const recallOf = (m: { recall: number | null }) => m.recall;

export async function benchPerturb(
  entryDirs: string[],
  config: RunConfig,
  deps: BenchDeps,
  opts: { twinsPerEntry: number; twinDumpDir: string; concurrency?: number },
): Promise<PerturbationReport> {
  const eligible = entryDirs.flatMap((dir) => {
    const entry = loadEntry(dir);
    if (entry.tier === "confirmed" && entry.manifest.vulns.length > 0) {
      return [{ dir, entry }];
    }
    console.error(
      `[perturb] ${entry.target}: SKIPPED — requires confirmed-tier entry with at least one vulnerability`,
    );
    return [];
  });
  if (eligible.length === 0) throw new Error("no perturbable entries");

  type Outcome =
    | { ok: true; result: PerturbationResult }
    | { ok: false; errored: ErroredEntry };
  const outcomes = await boundedMap(eligible, opts.concurrency ?? 1, async ({ dir, entry }): Promise<Outcome> => {
    const meter = new CostMeterCtor();
    try {
      try {
        const files = readEntryFiles(dir);

        // Score the original from a comment-stripped materialization — symmetric with
        // the twin's stripped comments, so the gap isolates rename robustness only.
        const stripped = await stripEntry(files);
        const origTargetDir = join(opts.twinDumpDir, `${entry.target}__orig`);
        mkdirSync(origTargetDir, { recursive: true });
        writeTwinDir(origTargetDir, stripped);
        const original = (await benchEntry(loadEntry(origTargetDir), config, deps, meter)).run;

        const twins = [];
        for (let i = 0; i < opts.twinsPerEntry; i++) {
          const twin = await generateTwin(files, twinSeed(entry.target, i));
          const twinDir = join(opts.twinDumpDir, `${entry.target}__${i}`);
          mkdirSync(twinDir, { recursive: true });
          writeTwinDir(twinDir, twin);
          twins.push((await benchEntry(loadEntry(twinDir), config, deps, meter)).run);
        }
        const g = perturbationGap(recallOf(original.metrics), twins.map((t) => recallOf(t.metrics)));
        return {
          ok: true,
          result: {
            target: entry.target,
            original: original.metrics,
            twins: twins.map((t) => t.metrics),
            recall_original: g.original,
            recall_twin_mean: g.twin_mean,
            perturbation_gap: g.gap,
          },
        };
      } catch (err) {
        if (
          !(err instanceof InfraError) &&
          !(err instanceof AgentError) &&
          !(err instanceof RefusalError)
        )
          throw err;
        console.error(`[perturb] ${entry.target}: ERRORED — excluded from perturbation gap, rerun to complete`);
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
  const results = outcomes
    .filter((outcome): outcome is { ok: true; result: PerturbationResult } => outcome.ok)
    .map((outcome) => outcome.result);
  const erroredEntries = outcomes
    .filter((outcome): outcome is { ok: false; errored: ErroredEntry } => !outcome.ok)
    .map((outcome) => outcome.errored);
  // Assemble the report inline (macro_gap = mean of non-null per-entry gaps).
  const gaps = results.map((r) => r.perturbation_gap).filter((x): x is number => x !== null);
  const macro_gap = gaps.length === 0 ? null : gaps.reduce((a, b) => a + b, 0) / gaps.length;
  return {
    complete: erroredEntries.length === 0,
    scored: results.length,
    errored: erroredEntries.length,
    erroredEntries,
    perEntry: results,
    macro_gap,
  };
}
