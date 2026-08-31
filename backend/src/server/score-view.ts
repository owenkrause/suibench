// Submitter-safe projection of a stored `RunScore`. The stored score is the
// FULL grader output — including `labels[]`, the ground-truth vuln list
// (the answer key, with entries the submitter MISSED) and each finding's
// `matched_label` (which names the ground-truth vuln it hit). Neither may
// ever reach the submitter. This is the ONLY place a `RunScore` is allowed
// to cross the API boundary, and it builds its output by an explicit
// allowlist (never a spread) so a future `RunScore` field can't silently
// leak through.
export interface SubmitterFinding {
  id: string;
  title: string;
  classification: "TP" | "FP" | "UNATTRIBUTED";
  confirmed: boolean;
}

export interface SubmitterScore {
  metrics: {
    precision: number | null;
    recall: number | null;
    attribution_rate: number | null;
    true_positives: number;
    false_positives: number;
    unattributed_findings: number;
  };
  findings: SubmitterFinding[];
}

function isClassification(v: unknown): v is SubmitterFinding["classification"] {
  return v === "TP" || v === "FP" || v === "UNATTRIBUTED";
}

/** The stored score arrives as `unknown` (jsonb) — read fields defensively. */
export function toSubmitterView(score: unknown): SubmitterScore {
  const s = (score ?? {}) as Record<string, unknown>;

  const rawFindings = Array.isArray(s.findings) ? s.findings : [];
  const findings: SubmitterFinding[] = rawFindings.map((f) => {
    const r = (f ?? {}) as Record<string, unknown>;
    return {
      id: typeof r.id === "string" ? r.id : "",
      title: typeof r.title === "string" ? r.title : "",
      classification: isClassification(r.classification) ? r.classification : "FP",
      confirmed: r.confirmed === true,
    };
  });

  const m = (s.metrics ?? {}) as Record<string, unknown>;
  const num = (v: unknown): number | null => (typeof v === "number" ? v : null);
  const count = (v: unknown): number => (typeof v === "number" ? v : 0);

  return {
    metrics: {
      precision: num(m.precision),
      recall: num(m.recall),
      attribution_rate: num(m.attribution_rate),
      true_positives: count(m.true_positives),
      false_positives: count(m.false_positives),
      unattributed_findings: count(m.unattributed_findings),
    },
    findings,
  };
}
