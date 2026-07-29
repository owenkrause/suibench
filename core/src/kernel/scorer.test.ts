import { describe, it, expect, vi } from "vitest";
import type { Finding, Attribution } from "./types.js";
import {
  scoreFindings,
  scoreDetect,
  scoreConfirmed,
  type GroundTruth,
  type VulnLabel,
  type JudgeFn,
} from "./scorer.js";

function label(over: Partial<VulnLabel>): VulnLabel {
  return {
    id: "l",
    module: "m",
    title: "t",
    severity: "high",
    root_cause: "rc",
    ...over,
  };
}
function finding(over: Partial<Finding>): Finding {
  return {
    id: "vuln-001",
    module: "m",
    severity: "high",
    title: "f",
    description: "d",
    ...over,
  };
}
const neverJudge: JudgeFn = async () => null;
const alwaysJudge: JudgeFn = async () => 0;
const byTitle: JudgeFn = async (f, candidates) => {
  const i = candidates.findIndex((c) => c.title === f.title);
  return i === -1 ? null : i;
};

describe("scoreDetect — judge ONLY (no exploit, no attribution)", () => {
  it("rejects duplicate label ids", async () => {
    const gt: GroundTruth = {
      target: "x",
      vulns: [label({ id: "dup" }), label({ id: "dup" })],
    };
    await expect(scoreDetect([], gt, neverJudge)).rejects.toThrow(
      /duplicate label id/,
    );
  });

  it("judge-matched finding -> TP; label HIT; recall counts", async () => {
    const gt: GroundTruth = { target: "x", vulns: [label({ title: "A" })] };
    const r = await scoreDetect([finding({})], gt, alwaysJudge);
    expect(r.findings[0].classification).toBe("TP");
    expect(r.labels[0].status).toBe("HIT");
    expect(r.metrics.tier).toBe("detect");
    expect(r.metrics.true_positives).toBe(1);
    expect(r.metrics.recall).toBe(1);
  });

  it("unmatched finding -> FP; label MISS; recall 0", async () => {
    const gt: GroundTruth = { target: "x", vulns: [label({ title: "A" })] };
    const r = await scoreDetect([finding({})], gt, neverJudge);
    expect(r.findings[0].classification).toBe("FP");
    expect(r.findings[0].matched_label).toBeNull();
    expect(r.labels[0].status).toBe("MISS");
    expect(r.metrics.recall).toBe(0);
  });

  it("recall = matched labels / labels_total across a multi-bug entry", async () => {
    const gt: GroundTruth = {
      target: "x",
      vulns: ["A", "B", "C", "D"].map((t) => label({ id: t, title: t })),
    };
    const two = ["A", "B"].map((t, i) => finding({ id: `v${i}`, title: t }));
    const r = await scoreDetect(two, gt, byTitle);
    expect(r.metrics.labels_total).toBe(4);
    expect(r.metrics.labels_hit).toBe(2);
    expect(r.metrics.recall).toBe(0.5);
  });

  it("finding-spam: precision DROPS as unmatched findings pile up", async () => {
    const gt: GroundTruth = { target: "x", vulns: [label({ title: "A" })] };
    // 1 real hit + 3 spam findings that match nothing.
    const findings = [
      finding({ id: "hit", title: "A" }),
      finding({ id: "spam1", title: "zzz" }),
      finding({ id: "spam2", title: "zzz" }),
      finding({ id: "spam3", title: "zzz" }),
    ];
    const r = await scoreDetect(findings, gt, byTitle);
    expect(r.metrics.recall).toBe(1); // the bug WAS found
    expect(r.metrics.true_positives).toBe(1);
    expect(r.metrics.false_positives).toBe(3);
    expect(r.metrics.precision).toBe(0.25); // spam tanks precision
  });

  it("severity_accuracy scored on matched labels only", async () => {
    const gt: GroundTruth = {
      target: "x",
      vulns: [label({ title: "A", severity: "critical" })],
    };
    const r = await scoreDetect(
      [finding({ severity: "low" })],
      gt,
      alwaysJudge,
    );
    expect(r.labels[0].severity_correct).toBe(false);
    expect(r.metrics.severity_accuracy).toBe(0);
  });

  it("carries the label harm tag (default state)", async () => {
    const gt: GroundTruth = {
      target: "x",
      vulns: [
        label({ id: "denial", title: "denial", harm: "availability" }),
        label({ id: "drain", title: "drain" }),
      ],
    };
    const findings = ["denial", "drain"].map((t, i) =>
      finding({ id: `v${i}`, title: t }),
    );
    const r = await scoreDetect(findings, gt, byTitle);
    expect(r.labels.find((l) => l.title === "denial")!.harm).toBe(
      "availability",
    );
    expect(r.labels.find((l) => l.title === "drain")!.harm).toBe("state");
  });

  it("no findings -> precision null, recall 0, severity null", async () => {
    const gt: GroundTruth = { target: "x", vulns: [label({ title: "A" })] };
    const r = await scoreDetect([], gt, neverJudge);
    expect(r.metrics.recall).toBe(0);
    expect(r.metrics.precision).toBeNull();
    expect(r.metrics.severity_accuracy).toBeNull();
  });

  describe("negative entries (vulns: [])", () => {
    const negativeGt: GroundTruth = { target: "x", vulns: [] };

    it("no findings on a negative -> everything null, judge never called", async () => {
      const judgeSpy = vi.fn(async () => null);
      const r = await scoreDetect([], negativeGt, judgeSpy);
      expect(r.metrics.labels_total).toBe(0);
      expect(r.metrics.recall).toBeNull();
      expect(r.metrics.precision).toBeNull();
      expect(r.metrics.severity_accuracy).toBeNull();
      expect(judgeSpy).not.toHaveBeenCalled();
    });

    it("a finding on a negative -> FP, precision 0, judge never called", async () => {
      const judgeSpy = vi.fn(async () => 0);
      const r = await scoreDetect([finding({})], negativeGt, judgeSpy);
      expect(r.findings[0].classification).toBe("FP");
      expect(r.metrics.false_positives).toBe(1);
      expect(r.metrics.precision).toBe(0);
      expect(r.metrics.recall).toBeNull();
      expect(judgeSpy).not.toHaveBeenCalled();
    });
  });
});

describe("scoreConfirmed — attribution ONLY (no judge)", () => {
  const gt3: GroundTruth = {
    target: "x",
    vulns: [
      label({ id: "a", title: "A" }),
      label({ id: "b", title: "B" }),
      label({ id: "c", title: "C" }),
    ],
  };
  const findings = ["A", "B", "C", "D"].map((t, i) =>
    finding({ id: `F${i + 1}`, title: t }),
  );

  it("recall = |confirmedLabels| / labels_total", () => {
    const attribution: Attribution = {
      perExploit: { F1: ["a"], F2: ["b"], F3: [] },
      confirmedLabels: ["a", "b"],
    };
    const r = scoreConfirmed(findings, gt3, attribution);
    expect(r.metrics.tier).toBe("confirmed");
    expect(r.metrics.recall).toBeCloseTo(2 / 3);
  });

  it("precision = attributed / exploitCarrying; empty perExploit is the FP", () => {
    // F1,F2 attributed; F3 (patch-invariant) + F4 (base=false) both EMPTY.
    const attribution: Attribution = {
      perExploit: { F1: ["a"], F2: ["b"], F3: [], F4: [] },
      confirmedLabels: ["a", "b"],
    };
    const r = scoreConfirmed(findings, gt3, attribution);
    expect(r.metrics.findings_total).toBe(4); // exploit-carrying
    expect(r.metrics.true_positives).toBe(2); // attributed
    expect(r.metrics.false_positives).toBe(2); // F3 + F4, empty perExploit
    expect(r.metrics.precision).toBeCloseTo(2 / 4);
  });

  it("a base=false exploit AND a base=true-patch-invariant exploit BOTH count as false_positives", () => {
    // F1 attributes to a; F3 is patch-invariant (base=true, no patch broke it);
    // F4 never worked (base=false). Both F3 and F4 have EMPTY perExploit.
    const attribution: Attribution = {
      perExploit: { F1: ["a"], F3: [], F4: [] },
      confirmedLabels: ["a"],
    };
    const r = scoreConfirmed(findings, gt3, attribution);
    expect(r.metrics.true_positives).toBe(1);
    expect(r.metrics.false_positives).toBe(2);
    const fps = r.findings
      .filter((f) => f.classification === "FP")
      .map((f) => f.id)
      .sort();
    expect(fps).toEqual(["F3", "F4"]);
  });

  it("severity_accuracy = exploit severity vs attributed label severity", () => {
    const gt: GroundTruth = {
      target: "x",
      vulns: [label({ id: "a", title: "A", severity: "critical" })],
    };
    // exploit F1 (severity high) attributes to a (critical) -> wrong.
    const attribution: Attribution = {
      perExploit: { F1: ["a"] },
      confirmedLabels: ["a"],
    };
    const f = [finding({ id: "F1", severity: "high" })];
    const r = scoreConfirmed(f, gt, attribution);
    expect(r.metrics.severity_accuracy).toBe(0);
  });

  it("precision null when nothing carried an exploit", () => {
    const empty: Attribution = { perExploit: {}, confirmedLabels: [] };
    const r = scoreConfirmed(findings, gt3, empty);
    expect(r.metrics.recall).toBe(0);
    expect(r.metrics.precision).toBeNull();
    expect(r.metrics.severity_accuracy).toBeNull();
  });

  it("the judge is never consulted (attribution is the sole grader)", async () => {
    const judgeSpy = vi.fn(async () => 0);
    const attribution: Attribution = {
      perExploit: { F1: ["a"] },
      confirmedLabels: ["a"],
    };
    const r = await scoreFindings(findings, gt3, judgeSpy, true, attribution);
    expect(r.metrics.tier).toBe("confirmed");
    expect(r.metrics.recall).toBeCloseTo(1 / 3);
    expect(judgeSpy).not.toHaveBeenCalled();
  });
});

describe("scoreFindings — tier dispatch", () => {
  const gt: GroundTruth = { target: "x", vulns: [label({ title: "A" })] };

  it("confirmable=false routes to detect (judge)", async () => {
    const r = await scoreFindings([finding({})], gt, alwaysJudge, false);
    expect(r.metrics.tier).toBe("detect");
    expect(r.findings[0].classification).toBe("TP");
  });

  it("confirmable=true routes to confirmed and requires an attribution", async () => {
    await expect(
      scoreFindings([finding({})], gt, alwaysJudge, true),
    ).rejects.toThrow(/requires an Attribution/);
  });
});
