// The scorecard hierarchy — three levels on two aggregation axes:
//   runs → entry   (pass@k)
//   entries → corpus (micro / macro)
//
// `RunScore` is the leaf (one entry, one attempt). `EntryScore` rolls k runs
// into one entry. `CorpusScore` rolls entries into micro (pool all
// labels/findings, one metric over the pool) + macro (average the per-entry
// metrics). This replaces the flat `Scorecard`: `ScoreMetrics` (snake_case) is
// the leaf number-bag, one naming convention throughout.
import type { LabelResult, FindingResult, ScoreMetrics } from "./scorer.js";

/** One entry, one attempt — the leaf. */
export interface RunScore {
  labels: LabelResult[];
  findings: FindingResult[];
  metrics: ScoreMetrics;
}

/** pass@k rollup over K runs of one entry (only present when k > 1). */
export interface PassK {
  runs: RunScore[];
  /** fraction of runs that hit ≥1 label (labels_hit > 0). */
  passRate: number;
  /** mean recall across runs. */
  mean: number;
  /** population variance of recall across runs. */
  variance: number;
}

/**
 * One entry. k=1 is a single `RunScore` (no `passk`); k>1 carries the rollup.
 * `run` is always the representative single run (the first, for k>1) so a reader
 * has one `ScoreMetrics` per entry regardless of k.
 */
export interface EntryScore {
  target: string;
  run: RunScore;
  passk?: PassK;
}

/** An entry the grader could not score (infra failure), kept OUT of `entries`
 *  so it never counts as a zero or a hit. `micro`/`macro` cover scored entries
 *  only; a run with any errored entry is not `complete`. */
export interface ErroredEntry {
  target: string;
  error: string;
  attempts: number;
}

/** entries → corpus, both axes. `macro_gap` only when twin-paired. */
export interface CorpusScore {
  /** false iff any entry errored — the aggregate covers scored entries only. */
  complete: boolean;
  scored: number;
  errored: number;
  micro: ScoreMetrics;
  macro: ScoreMetrics;
  entries: EntryScore[];
  erroredEntries: ErroredEntry[];
  macro_gap?: number;
}

/** null-safe mean over the non-null values; null if none are non-null. */
function meanOrNull(xs: (number | null)[]): number | null {
  const vals = xs.filter((x): x is number => x !== null);
  if (vals.length === 0) return null;
  return vals.reduce((a, b) => a + b, 0) / vals.length;
}

/**
 * MICRO — pool every entry's raw counts, then divide ONCE (label-weighted for
 * recall, finding-weighted for precision). This is the aggregate that respects
 * per-entry size: a big entry moves the number more than a tiny one.
 */
function microMetrics(entries: EntryScore[]): ScoreMetrics {
  let labelsTotal = 0;
  let labelsHit = 0;
  let findingsTotal = 0;
  let truePositives = 0;
  let falsePositives = 0;
  let unattributedFindings = 0;
  let confirmedTruePositives = 0;
  // severity_accuracy pools its own raw numerator/denominator — no float
  // round-trip, and the denominator varies by tier (carried in ScoreMetrics).
  let sevTotal = 0;
  let sevCorrect = 0;
  const tiers = new Set<ScoreMetrics["tier"]>();

  for (const e of entries) {
    const m = e.run.metrics;
    tiers.add(m.tier);
    labelsTotal += m.labels_total;
    labelsHit += m.labels_hit;
    findingsTotal += m.findings_total;
    truePositives += m.true_positives;
    falsePositives += m.false_positives;
    unattributedFindings += m.unattributed_findings;
    if (m.tier === "confirmed") confirmedTruePositives += m.true_positives;
    sevTotal += m.severity_total;
    sevCorrect += m.severity_correct;
  }

  const tier = tiers.size === 1 ? [...tiers][0] : "confirmed";
  return {
    tier,
    labels_total: labelsTotal,
    labels_hit: labelsHit,
    findings_total: findingsTotal,
    true_positives: truePositives,
    false_positives: falsePositives,
    unattributed_findings: unattributedFindings,
    recall: labelsTotal === 0 ? null : labelsHit / labelsTotal,
    precision:
      truePositives + falsePositives === 0
        ? null
        : truePositives / (truePositives + falsePositives),
    attribution_rate:
      confirmedTruePositives + unattributedFindings === 0
        ? null
        : confirmedTruePositives / (confirmedTruePositives + unattributedFindings),
    severity_accuracy: sevTotal === 0 ? null : sevCorrect / sevTotal,
    severity_correct: sevCorrect,
    severity_total: sevTotal,
  };
}

/**
 * MACRO — average the per-entry metrics, entry-weighted (each entry counts
 * once, regardless of size). Counts are summed for reference; the rates are
 * null-safe means of the per-entry rates.
 */
function macroMetrics(entries: EntryScore[]): ScoreMetrics {
  const ms = entries.map((e) => e.run.metrics);
  const tiers = new Set(ms.map((m) => m.tier));
  const tier = tiers.size === 1 ? [...tiers][0] : "confirmed";
  return {
    tier,
    labels_total: ms.reduce((a, m) => a + m.labels_total, 0),
    labels_hit: ms.reduce((a, m) => a + m.labels_hit, 0),
    findings_total: ms.reduce((a, m) => a + m.findings_total, 0),
    true_positives: ms.reduce((a, m) => a + m.true_positives, 0),
    false_positives: ms.reduce((a, m) => a + m.false_positives, 0),
    unattributed_findings: ms.reduce((a, m) => a + m.unattributed_findings, 0),
    recall: meanOrNull(ms.map((m) => m.recall)),
    precision: meanOrNull(ms.map((m) => m.precision)),
    attribution_rate: meanOrNull(ms.map((m) => m.attribution_rate)),
    severity_accuracy: meanOrNull(ms.map((m) => m.severity_accuracy)),
    severity_correct: ms.reduce((a, m) => a + m.severity_correct, 0),
    severity_total: ms.reduce((a, m) => a + m.severity_total, 0),
  };
}

/**
 * entries → corpus. `micro` pools labels/findings (label-weighted), `macro`
 * averages the per-entry rates (entry-weighted). k>1 entries fold to their
 * representative `run` before aggregation (pass@k already happened upstream).
 */
export function aggregateCorpus(
  entries: EntryScore[],
  erroredEntries: ErroredEntry[] = [],
): CorpusScore {
  return {
    complete: erroredEntries.length === 0,
    scored: entries.length,
    errored: erroredEntries.length,
    micro: microMetrics(entries),
    macro: macroMetrics(entries),
    entries,
    erroredEntries,
  };
}
