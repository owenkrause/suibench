// The suibench-level RunReport: the kernel score wrapped with cost (accounting)
// and manifest (provenance). Neither enters a score type — this is the driver's
// assembly + persistence layer. One writer serves both the recall/precision
// CorpusScore and the patch-rate PatchCorpusScore (both expose `entries[].target`).
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CorpusScore, ErroredEntry, PatchCorpusScore, ScoreMetrics } from "core";
import type { CostTotals } from "core/runtime";
import type { RunManifest } from "../adapters/manifest.js";

export type EntryCost = CostTotals;

export interface CorpusCost {
  perEntry: Record<string, EntryCost>;
  total: EntryCost;
}

export interface RunReport<S> {
  score: S;
  cost: CorpusCost;
  manifest: RunManifest;
  perturbation?: PerturbationReport;
}

// Perturbation gap: how much recall drops from the original entry to its
// twins (paraphrased/renamed variants). Read from ScoreMetrics.recall only —
// no provenance carried here (that's read downstream from SOURCE.md).
export interface PerturbationResult {
  target: string;
  original: ScoreMetrics;
  twins: ScoreMetrics[];
  recall_original: number | null;
  recall_twin_mean: number | null;
  perturbation_gap: number | null;
}

export interface PerturbationReport {
  /** false iff a perturbation target could not be scored. */
  complete: boolean;
  /** Successful original+twin perturbation scores. */
  scored: number;
  /** Expected policy/infra failures excluded from the gap. */
  errored: number;
  /** Durable descriptions of targets that must be rerun. */
  erroredEntries: ErroredEntry[];
  perEntry: PerturbationResult[];
  macro_gap: number | null;
}

// The per-entry gap. Null-safe: null if the original has no recall, or if every
// twin does (mean is over non-null twins only). The driver assembles the
// PerturbationReport (macro_gap = mean of non-null per-entry gaps) inline.
export function perturbationGap(original: number | null, twins: (number | null)[]) {
  const present = twins.filter((x): x is number => x !== null);
  const twin_mean =
    present.length === 0
      ? null
      : present.reduce((a, b) => a + b, 0) / present.length;
  const gap = original === null || twin_mean === null ? null : original - twin_mean;
  return { gap, original, twin_mean, twins };
}

export interface RunDirConfig {
  axis: string;
  harness: string;
  model: string;
  judgeModel: string;
  k: number;
  concurrency: number;
  maxTurns: number;
  effort: string;
  dataset: string;
  filter: string | null;
  requestedTargets: string[];
  images: { untrusted: string; confirmer: string; gate: string };
}

export class CostCollector {
  private readonly perEntry: Record<string, EntryCost> = {};

  record(target: string, cost: EntryCost): void {
    this.perEntry[target] = cost;
  }

  corpusCost(): CorpusCost {
    const total: EntryCost = { turns: 0, inputTokens: 0, outputTokens: 0 };
    for (const c of Object.values(this.perEntry)) {
      total.turns += c.turns;
      total.inputTokens += c.inputTokens;
      total.outputTokens += c.outputTokens;
    }
    return { perEntry: { ...this.perEntry }, total };
  }
}

function jsonReplacer(_k: string, v: unknown): unknown {
  return typeof v === "bigint" ? v.toString() : v;
}

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, jsonReplacer, 2));
}

export function writeRunReport(
  dir: string,
  report: RunReport<CorpusScore | PatchCorpusScore>,
  config: RunDirConfig,
): void {
  mkdirSync(dir, { recursive: true });
  writeJson(join(dir, "manifest.json"), report.manifest);
  if (report.perturbation) {
    writeJson(join(dir, "perturbation.json"), report.perturbation);
  }

  const { entries, ...scoreSummary } = report.score;
  writeJson(join(dir, "corpus.json"), {
    config,
    cost: report.cost.total,
    ...scoreSummary,
    entryTargets: entries.map((e) => e.target),
  });

  for (const entry of entries) {
    const entryDir = join(dir, "entries", entry.target);
    mkdirSync(entryDir, { recursive: true });
    writeJson(join(entryDir, "scorecard.json"), {
      score: entry,
      cost: report.cost.perEntry[entry.target] ?? null,
    });
  }

  for (const error of report.score.erroredEntries) {
    const entryDir = join(dir, "entries", error.target);
    mkdirSync(entryDir, { recursive: true });
    writeJson(join(entryDir, "scorecard.json"), {
      error,
      cost: report.cost.perEntry[error.target] ?? null,
    });
  }
}
