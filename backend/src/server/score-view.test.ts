// Regression guard for the P0 leak: the submitter-facing projection MUST NOT
// carry the ground-truth `labels[]` (the answer key) or any `matched_label`
// (which names the ground-truth vuln a finding hit).
import { describe, expect, it } from "vitest";
import { toSubmitterView } from "./score-view.js";

const SECRET_LABEL_TITLE_1 = "Reentrancy in withdraw_penalty allows double-spend";
const SECRET_LABEL_TITLE_2 = "Missing capability check on admin_mint";
const SECRET_MATCHED_LABEL = "vuln-reentrancy-001";

// A realistic full RunScore, as actually stored in `benchmark_submissions.score`.
const fullRunScore = {
  labels: [
    {
      id: SECRET_MATCHED_LABEL,
      title: SECRET_LABEL_TITLE_1,
      severity: "critical",
      harm: "asset",
      status: "HIT",
      matched_finding: "finding-1",
      severity_correct: true,
    },
    {
      id: "vuln-admin-mint-002",
      title: SECRET_LABEL_TITLE_2,
      severity: "high",
      harm: "state",
      status: "MISS",
      matched_finding: null,
      severity_correct: null,
    },
  ],
  findings: [
    {
      id: "finding-1",
      title: "Double withdrawal via reentrant call",
      classification: "TP",
      matched_label: SECRET_MATCHED_LABEL,
      confirmed: true,
    },
    {
      id: "finding-2",
      title: "Unrelated FP finding",
      classification: "FP",
      matched_label: null,
      confirmed: false,
    },
  ],
  metrics: {
    tier: "confirmed",
    labels_total: 2,
    labels_hit: 1,
    findings_total: 2,
    true_positives: 1,
    false_positives: 1,
    unattributed_findings: 0,
    recall: 0.5,
    precision: 0.5,
    attribution_rate: 1,
    severity_accuracy: 1,
    severity_correct: 1,
    severity_total: 1,
  },
};

describe("toSubmitterView", () => {
  const view = toSubmitterView(fullRunScore);
  const serialized = JSON.stringify(view);

  it("has no labels key anywhere in the output", () => {
    expect(view).not.toHaveProperty("labels");
    expect(serialized).not.toMatch(/"labels"/);
  });

  it("does not leak ground-truth label titles", () => {
    expect(serialized).not.toContain(SECRET_LABEL_TITLE_1);
    expect(serialized).not.toContain(SECRET_LABEL_TITLE_2);
  });

  it("does not leak matched_label values or key", () => {
    expect(serialized).not.toContain(SECRET_MATCHED_LABEL);
    expect(serialized).not.toMatch(/"matched_label"/);
  });

  it("does not leak labels_total/labels_hit", () => {
    expect(serialized).not.toMatch(/"labels_total"/);
    expect(serialized).not.toMatch(/"labels_hit"/);
  });

  it("preserves id/title/classification/confirmed on each finding, with no matched_label key", () => {
    expect(view.findings).toEqual([
      { id: "finding-1", title: "Double withdrawal via reentrant call", classification: "TP", confirmed: true },
      { id: "finding-2", title: "Unrelated FP finding", classification: "FP", confirmed: false },
    ]);
    for (const f of view.findings) {
      expect(f).not.toHaveProperty("matched_label");
    }
  });

  it("metrics has exactly the 6 allowlisted fields, no labels_total/labels_hit/severity_*", () => {
    expect(Object.keys(view.metrics).sort()).toEqual(
      [
        "attribution_rate",
        "false_positives",
        "precision",
        "recall",
        "true_positives",
        "unattributed_findings",
      ].sort(),
    );
    expect(view.metrics).toEqual({
      precision: 0.5,
      recall: 0.5,
      attribution_rate: 1,
      true_positives: 1,
      false_positives: 1,
      unattributed_findings: 0,
    });
  });

  it("handles a null/undefined score without throwing", () => {
    expect(toSubmitterView(null)).toEqual({
      metrics: {
        precision: null,
        recall: null,
        attribution_rate: null,
        true_positives: 0,
        false_positives: 0,
        unattributed_findings: 0,
      },
      findings: [],
    });
  });
});
