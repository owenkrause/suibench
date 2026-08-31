import { describe, it, expect } from "vitest";
import {
  aggregateCorpus,
  type RunScore,
  type EntryScore,
} from "./scorecard.js";
import type { ScoreMetrics } from "./scorer.js";

/** A minimal RunScore carrying just the metrics the aggregator reads. */
function run(m: Partial<ScoreMetrics>): RunScore {
  return {
    labels: [],
    findings: [],
    metrics: {
      tier: "detect",
      labels_total: 0,
      labels_hit: 0,
      findings_total: 0,
      true_positives: 0,
      false_positives: 0,
      unattributed_findings: 0,
      recall: null,
      precision: null,
      attribution_rate: null,
      severity_accuracy: null,
      severity_correct: 0,
      severity_total: 0,
      ...m,
    },
  };
}
function entry(target: string, m: Partial<ScoreMetrics>): EntryScore {
  return { target, run: run(m) };
}

describe("aggregateCorpus — micro vs macro", () => {
  it("entry A 1/1, entry B 3/9 -> micro 40%, macro ~66.7%", () => {
    const entries = [
      entry("A", { labels_total: 1, labels_hit: 1, recall: 1 }),
      entry("B", { labels_total: 9, labels_hit: 3, recall: 3 / 9 }),
    ];
    const c = aggregateCorpus(entries);

    // micro pools labels: (1+3)/(1+9) = 4/10 = 0.40 exactly.
    expect(c.micro.labels_total).toBe(10);
    expect(c.micro.labels_hit).toBe(4);
    expect(c.micro.recall).toBeCloseTo(0.4, 10);

    // macro averages per-entry recall: (1 + 1/3)/2 = 0.6667 (~66.5% rounded).
    expect(c.macro.recall).toBeCloseTo((1 + 1 / 3) / 2, 10);
    expect(c.macro.recall).toBeCloseTo(0.6667, 3);
  });

  it("micro is label-weighted; macro is entry-weighted (they diverge)", () => {
    const entries = [
      entry("big", { labels_total: 100, labels_hit: 50, recall: 0.5 }),
      entry("tiny", { labels_total: 2, labels_hit: 2, recall: 1 }),
    ];
    const c = aggregateCorpus(entries);
    // micro: 52/102 ≈ 0.5098 — the big entry dominates.
    expect(c.micro.recall).toBeCloseTo(52 / 102, 10);
    // macro: (0.5 + 1)/2 = 0.75 — each entry counts once.
    expect(c.macro.recall).toBeCloseTo(0.75, 10);
  });

  it("micro precision pools findings; macro precision averages entry precision", () => {
    const entries = [
      entry("A", {
        findings_total: 4,
        true_positives: 1,
        false_positives: 3,
        precision: 0.25,
      }),
      entry("B", { findings_total: 1, true_positives: 1, precision: 1 }),
    ];
    const c = aggregateCorpus(entries);
    expect(c.micro.precision).toBeCloseTo(2 / 5, 10); // pooled TPs/findings
    expect(c.macro.precision).toBeCloseTo((0.25 + 1) / 2, 10);
  });

  it("micro precision excludes unattributed findings from its denominator", () => {
    const entries = [
      entry("confirmed", {
        tier: "confirmed",
        findings_total: 10,
        true_positives: 1,
        false_positives: 1,
        unattributed_findings: 8,
        precision: 0.5,
        attribution_rate: 1 / 9,
      }),
    ];

    const c = aggregateCorpus(entries);
    expect(c.micro.findings_total).toBe(10);
    expect(c.micro.precision).toBe(0.5);
  });

  it("micro attribution rate pools confirmed entries and excludes detect TPs", () => {
    const entries = [
      entry("detect", {
        tier: "detect",
        findings_total: 10,
        true_positives: 10,
        precision: 1,
        attribution_rate: null,
      }),
      entry("confirmed", {
        tier: "confirmed",
        findings_total: 4,
        true_positives: 1,
        false_positives: 1,
        unattributed_findings: 2,
        precision: 0.5,
        attribution_rate: 1 / 3,
      }),
    ];

    const c = aggregateCorpus(entries);
    expect(c.micro.attribution_rate).toBeCloseTo(1 / 3);
    expect(c.macro.attribution_rate).toBeCloseTo(1 / 3);
    expect(c.micro.unattributed_findings).toBe(2);
  });

  it("null rates are skipped in the macro mean (not counted as 0)", () => {
    const entries = [entry("A", { recall: 1 }), entry("B", { recall: null })];
    const c = aggregateCorpus(entries);
    expect(c.macro.recall).toBe(1); // only the non-null entry averaged
  });

  it("severity_accuracy: micro pools raw counts, macro means the rates", () => {
    const entries = [
      entry("A", { severity_accuracy: 1, severity_correct: 2, severity_total: 2 }),
      entry("B", { severity_accuracy: 0, severity_correct: 0, severity_total: 2 }),
    ];
    const c = aggregateCorpus(entries);
    // micro: (2 + 0)/(2 + 2) = 0.5 — pooled from the raw counts, no round-trip
    expect(c.micro.severity_accuracy).toBeCloseTo(0.5, 10);
    expect(c.micro.severity_correct).toBe(2);
    expect(c.micro.severity_total).toBe(4);
    // macro: (1 + 0)/2 = 0.5
    expect(c.macro.severity_accuracy).toBeCloseTo(0.5, 10);
  });

  it("mixed-tier corpus pools uniformly (tiers carry the same fields)", () => {
    const entries = [
      entry("detect", {
        tier: "detect",
        labels_total: 2,
        labels_hit: 1,
        recall: 0.5,
      }),
      entry("confirmed", {
        tier: "confirmed",
        labels_total: 2,
        labels_hit: 2,
        recall: 1,
      }),
    ];
    const c = aggregateCorpus(entries);
    expect(c.micro.recall).toBeCloseTo(3 / 4, 10);
    expect(c.macro.recall).toBeCloseTo(0.75, 10);
  });
});
