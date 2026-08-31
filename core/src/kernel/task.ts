// `Task` — an abstract producer of a `RunScore` from some input, plus the
// combinators that compose runs → entries → corpus. All I/O lives behind the
// injected `Task`; the combinators themselves are pure compositions over
// `RunScore`/`EntryScore` values.
import type { ExploitRun, AttributionResult } from "./counterfactual.js";
import { attribute } from "./counterfactual.js";
import type { RunScore, EntryScore, PassK } from "./scorecard.js";

/**
 * A `Task` grades one entry once, given whatever input the caller pins (an
 * entry + an agent run in the real driver — abstract here so the kernel stays
 * pure). Stays a producer of a `RunScore`; the combinators below never
 * inspect A.
 */
export type Task<A> = (input: A) => Promise<RunScore>;

/** How to fold K `RunScore`s into the entry's representative single run. */
export type Fold = (runs: RunScore[]) => RunScore;

/** The first run represents the entry. */
export const firstRun: Fold = (runs) => runs[0];

/** pass@k: the best of the k runs (max recall, ties broken by precision). */
export const bestRun: Fold = (runs) =>
  runs.reduce((best, r) => {
    const rr = r.metrics.recall ?? 0;
    const br = best.metrics.recall ?? 0;
    if (rr !== br) return rr > br ? r : best;
    return (r.metrics.precision ?? 0) > (best.metrics.precision ?? 0)
      ? r
      : best;
  });

function passRate(runs: RunScore[]): number {
  const hits = runs.filter((r) => r.metrics.labels_hit > 0).length;
  return hits / runs.length;
}

function recallStats(runs: RunScore[]): { mean: number; variance: number } {
  const rs = runs.map((r) => r.metrics.recall ?? 0);
  const mean = rs.reduce((a, b) => a + b, 0) / rs.length;
  const variance = rs.reduce((a, b) => a + (b - mean) ** 2, 0) / rs.length;
  return { mean, variance };
}

/**
 * runs → entry (pass@k). Runs the task `k` times and rolls up. `k=1` is the
 * identity: a single `RunScore`, no `passk` field (byte-identical to the
 * single-run path). `fold` picks the representative run for the `EntryScore`.
 */
export async function passK<A>(
  k: number,
  input: A,
  target: string,
  task: Task<A>,
  fold: Fold = bestRun,
): Promise<EntryScore> {
  if (k <= 1) {
    return { target, run: await task(input) };
  }
  const runs: RunScore[] = [];
  for (let i = 0; i < k; i++) runs.push(await task(input));
  const { mean, variance } = recallStats(runs);
  const passk: PassK = { runs, passRate: passRate(runs), mean, variance };
  return { target, run: fold(runs), passk };
}

/**
 * A twin-paired evaluation: the entry and its perturbation twin, each scored,
 * plus the per-pair `perturbation_gap` (original recall − twin recall) — a
 * lower bound on surface memorization.
 */
export interface TwinPairScore {
  original: EntryScore;
  twin: EntryScore;
  perturbation_gap: number;
}

/**
 * twin combinator: score both sides of a twin pair with the same task and
 * report the per-pair `perturbation_gap`. The corpus `macro_gap` is the mean of
 * these gaps, computed by the corpus aggregator over the paired entries.
 */
export async function twinPair<A>(
  original: { input: A; target: string },
  twin: { input: A; target: string },
  task: Task<A>,
): Promise<TwinPairScore> {
  const o = await passK(1, original.input, original.target, task);
  const t = await passK(1, twin.input, twin.target, task);
  const gap = (o.run.metrics.recall ?? 0) - (t.run.metrics.recall ?? 0);
  return { original: o, twin: t, perturbation_gap: gap };
}

/** corpus `macro_gap` = mean per-pair perturbation gap. */
export function macroGap(pairs: TwinPairScore[]): number {
  if (pairs.length === 0) return 0;
  return pairs.reduce((a, p) => a + p.perturbation_gap, 0) / pairs.length;
}

/**
 * counterfactual combinator — wraps the existing pure `attribute()` over the
 * per-script runs. Kept as a thin combinator so callers compose attribution the
 * same way they compose the other run-producers, without reimplementing the
 * set-logic.
 */
export function counterfactual(runs: ExploitRun[]): AttributionResult {
  return attribute(runs);
}
