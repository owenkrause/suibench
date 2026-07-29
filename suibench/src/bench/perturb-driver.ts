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
import type { RunConfig, BenchDeps } from "./driver.js";
import { benchEntry } from "./driver.js";
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
  const results = await boundedMap(entryDirs, opts.concurrency ?? 1, async (dir): Promise<PerturbationResult> => {
    const files = readEntryFiles(dir);

    // Score the original from a comment-stripped materialization — symmetric with
    // the twin's stripped comments, so the gap isolates rename robustness only.
    const stripped = await stripEntry(files);
    const entry = loadEntry(dir);
    const origTargetDir = join(opts.twinDumpDir, `${entry.target}__orig`);
    mkdirSync(origTargetDir, { recursive: true });
    writeTwinDir(origTargetDir, stripped);
    const original = (await benchEntry(loadEntry(origTargetDir), config, deps)).run;

    const twins = [];
    for (let i = 0; i < opts.twinsPerEntry; i++) {
      const twin = await generateTwin(files, twinSeed(entry.target, i));
      const twinDir = join(opts.twinDumpDir, `${entry.target}__${i}`);
      mkdirSync(twinDir, { recursive: true });
      writeTwinDir(twinDir, twin);
      twins.push((await benchEntry(loadEntry(twinDir), config, deps)).run);
    }
    const g = perturbationGap(recallOf(original.metrics), twins.map((t) => recallOf(t.metrics)));
    return {
      target: entry.target,
      original: original.metrics,
      twins: twins.map((t) => t.metrics),
      recall_original: g.original,
      recall_twin_mean: g.twin_mean,
      perturbation_gap: g.gap,
    };
  });
  // Assemble the report inline (macro_gap = mean of non-null per-entry gaps).
  const gaps = results.map((r) => r.perturbation_gap).filter((x): x is number => x !== null);
  const macro_gap = gaps.length === 0 ? null : gaps.reduce((a, b) => a + b, 0) / gaps.length;
  return { perEntry: results, macro_gap };
}
