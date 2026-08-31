import { describe, it, expect, vi } from "vitest";
import {
  passK,
  twinPair,
  macroGap,
  counterfactual,
  firstRun,
  bestRun,
  type Task,
} from "./task.js";
import type { RunScore } from "./scorecard.js";
import type { ScoreMetrics } from "./scorer.js";

function run(m: Partial<ScoreMetrics>): RunScore {
  return {
    labels: [],
    findings: [],
    metrics: {
      tier: "detect",
      labels_total: 1,
      labels_hit: 0,
      findings_total: 0,
      true_positives: 0,
      false_positives: 0,
      unattributed_findings: 0,
      recall: 0,
      precision: null,
      attribution_rate: null,
      severity_accuracy: null,
      severity_correct: 0,
      severity_total: 0,
      ...m,
    },
  };
}

describe("passK — runs → entry", () => {
  it("k=1 is the identity: single run, no passk field", async () => {
    const task: Task<null> = async () => run({ recall: 1, labels_hit: 1 });
    const e = await passK(1, null, "entry", task);
    expect(e.passk).toBeUndefined();
    expect(e.run.metrics.recall).toBe(1);
    expect(e.target).toBe("entry");
  });

  it("k>1 runs the task k times and rolls up passRate/mean/variance", async () => {
    // recalls: [1, 0, 1] -> 2/3 pass, mean 2/3, variance 2/9.
    const recalls = [1, 0, 1];
    let i = 0;
    const task: Task<null> = async () =>
      run({ recall: recalls[i], labels_hit: recalls[i++] });
    const e = await passK(3, null, "entry", task);
    expect(e.passk).toBeDefined();
    expect(e.passk!.runs).toHaveLength(3);
    expect(e.passk!.passRate).toBeCloseTo(2 / 3, 10);
    expect(e.passk!.mean).toBeCloseTo(2 / 3, 10);
    expect(e.passk!.variance).toBeCloseTo(2 / 9, 10);
  });

  it("default fold is pass@k — the best of the k runs, not the first", async () => {
    const recalls = [0.1, 0.9, 0.5];
    let i = 0;
    const task: Task<null> = async () => run({ recall: recalls[i++] });
    const best = await passK(3, null, "e", task);
    expect(best.run.metrics.recall).toBe(0.9);

    // an explicit firstRun fold still selects the first attempt.
    let j = 0;
    const task2: Task<null> = async () => run({ recall: recalls[j++] });
    const first = await passK(3, null, "e", task2, firstRun);
    expect(first.run.metrics.recall).toBe(0.1);
  });

  it("firstRun fold returns the first run", () => {
    const a = run({ recall: 0.1 });
    const b = run({ recall: 0.2 });
    expect(firstRun([a, b])).toBe(a);
  });

  it("bestRun fold picks max recall, breaking ties by precision", () => {
    const a = run({ recall: 0.5, precision: 0.9 });
    const b = run({ recall: 0.9, precision: 0.2 });
    expect(bestRun([a, b])).toBe(b); // higher recall wins

    const c = run({ recall: 0.7, precision: 0.3 });
    const d = run({ recall: 0.7, precision: 0.8 });
    expect(bestRun([c, d])).toBe(d); // tie on recall → higher precision
  });
});

describe("twinPair — perturbation gap", () => {
  it("gap = original recall − twin recall", async () => {
    const task: Task<{ side: "o" | "t" }> = async ({ side }) =>
      run({ recall: side === "o" ? 0.9 : 0.3 });
    const p = await twinPair(
      { input: { side: "o" }, target: "orig" },
      { input: { side: "t" }, target: "orig.twin" },
      task,
    );
    expect(p.perturbation_gap).toBeCloseTo(0.6, 10);
    expect(p.original.target).toBe("orig");
    expect(p.twin.target).toBe("orig.twin");
  });

  it("macroGap = mean per-pair gap", () => {
    const mk = (gap: number) => ({
      original: { target: "o", run: run({}) },
      twin: { target: "t", run: run({}) },
      perturbation_gap: gap,
    });
    expect(macroGap([mk(0.6), mk(0.2)])).toBeCloseTo(0.4, 10);
    expect(macroGap([])).toBe(0);
  });
});

describe("counterfactual — wraps attribute()", () => {
  it("delegates to the pure attribution set-logic", () => {
    const a = counterfactual([
      {
        exploitId: "F1",
        base: { witnesses: ["x", "y"] },
        perLabel: { x: { witnesses: ["y"] }, y: { witnesses: ["x", "y"] } },
      },
      { exploitId: "F2", base: { witnesses: [] }, perLabel: {} },
    ]);
    expect(a.perExploit["F1"]).toEqual({ kind: "attributed", labels: ["x"] });
    expect(a.perExploit["F2"]).toEqual({ kind: "refuted", labels: [] });
    expect(a.confirmedLabels).toEqual(["x"]);
  });

  it("historical tripwire shape: a single-witness base with an emptying own-patch is attributed to that witness only", () => {
    const a = counterfactual([
      {
        exploitId: "F3",
        base: { witnesses: ["collateral-release-no-repay"] },
        perLabel: {
          "collateral-release-no-repay": { witnesses: [] },
        },
      },
    ]);
    expect(a.perExploit["F3"]).toEqual({
      kind: "attributed",
      labels: ["collateral-release-no-repay"],
    });
  });

  it("refuted: an empty base witness set needs no patch results", () => {
    const a = counterfactual([
      { exploitId: "F4", base: { witnesses: [] }, perLabel: {} },
    ]);
    expect(a.perExploit["F4"]).toEqual({ kind: "refuted", labels: [] });
  });
});
