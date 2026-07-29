// Findings-vs-groundtruth scoring — pure.
//
// The two tiers are DISJOINT grading mechanisms:
//   detect    = LLM judge ONLY. Findings are reasoning artifacts (no exploit);
//               metrics come from judge matches (findings <-> labels).
//   confirmed = counterfactual Attribution ONLY, NO judge. Every finding IS an
//               exploit (1:1 with a `perExploit` entry); metrics come from
//               attribution set-logic.
//
// `ScoreMetrics` is a FLAT struct + a `tier` tag: the SAME field NAMES in both
// tiers (`recall`/`precision`/`severity_accuracy` + counts), only the matching
// mechanism differs. So a mixed-tier corpus pools uniformly.
import type { Finding, Severity, Harm, Attribution } from "./types.js";

export interface VulnLabel {
  /** Stable join key tying label ↔ patch ↔ attribution. Author-assigned, never
   *  derived from `title`, so a title edit can't silently re-key the label. */
  id: string;
  module: string;
  title: string;
  severity: Severity;
  root_cause: string;
  /** Harm modality; defaults to "state". */
  harm?: Harm;
}

export interface GroundTruth {
  target: string;
  vulns: VulnLabel[];
}

export interface LabelResult {
  id: string;
  title: string;
  severity: Severity;
  harm: Harm;
  status: "HIT" | "MISS";
  matched_finding: string | null;
  severity_correct: boolean | null;
}

export interface FindingResult {
  id: string;
  title: string;
  classification: "TP" | "FP";
  matched_label: string | null;
  confirmed: boolean;
}

/**
 * Flat metric bag + a `tier` tag. Both tiers carry the SAME fields; the `tier`
 * records which grader produced them (soft `JudgeFn` vs hard `base ∧ ¬patch`).
 * No prefixed/tier-exclusive fields — nothing is representable in one tier that
 * isn't in the other, so aggregation over a mixed corpus is well-defined.
 */
export interface ScoreMetrics {
  tier: "detect" | "confirmed";
  labels_total: number;
  labels_hit: number;
  findings_total: number;
  true_positives: number;
  false_positives: number;
  recall: number | null;
  precision: number | null;
  /** severity_correct / severity_total; null iff severity_total is 0. Carrying
   *  the raw counts (not just the rate) lets micro pool them exactly — the
   *  denominator differs by tier (hit labels vs attributed exploits). */
  severity_accuracy: number | null;
  severity_correct: number;
  severity_total: number;
}

/** Returns the index into `candidates` of the matching label, or null. */
export type JudgeFn = (
  finding: Finding,
  candidates: VulnLabel[],
) => Promise<number | null>;

/** The join keys must be unique within an entry, else attribution collides. */
function assertUniqueIds(vulns: VulnLabel[]): void {
  const seen = new Set<string>();
  for (const { id } of vulns) {
    if (seen.has(id)) throw new Error(`duplicate label id "${id}"`);
    seen.add(id);
  }
}

type Scored = {
  labels: LabelResult[];
  findings: FindingResult[];
  metrics: ScoreMetrics;
};

/** Detect tier — LLM judge ONLY. No exploit, no confirmation, no attribution. */
export async function scoreDetect(
  findings: Finding[],
  groundtruth: GroundTruth,
  judge: JudgeFn,
): Promise<Scored> {
  assertUniqueIds(groundtruth.vulns);
  const vulns = groundtruth.vulns;
  const isNegative = vulns.length === 0;
  // label id -> the first finding (with its severity) that judge-matched it.
  const claims = new Map<string, { findingId: string; severity: string }>();

  const findingResults: FindingResult[] = [];
  for (const f of findings) {
    const idx = isNegative ? null : await judge(f, vulns);
    const matchedId = idx !== null ? vulns[idx].id : null;
    findingResults.push({
      id: f.id,
      title: f.title,
      classification: matchedId !== null ? "TP" : "FP",
      matched_label: matchedId,
      confirmed: false,
    });
    if (matchedId && !claims.has(matchedId)) {
      claims.set(matchedId, { findingId: f.id, severity: f.severity });
    }
  }

  const labels: LabelResult[] = vulns.map((label) => {
    const claim = claims.get(label.id);
    return claim
      ? {
          id: label.id,
          title: label.title,
          severity: label.severity,
          harm: label.harm ?? "state",
          status: "HIT",
          matched_finding: claim.findingId,
          severity_correct: claim.severity === label.severity,
        }
      : {
          id: label.id,
          title: label.title,
          severity: label.severity,
          harm: label.harm ?? "state",
          status: "MISS",
          matched_finding: null,
          severity_correct: null,
        };
  });

  const labelsTotal = vulns.length;
  const labelsHit = claims.size;
  const findingsTotal = findings.length;
  const truePositives = findingResults.filter(
    (r) => r.classification === "TP",
  ).length;
  const falsePositives = findingsTotal - truePositives;
  const severityCorrect = labels.filter(
    (l) => l.status === "HIT" && l.severity_correct === true,
  ).length;

  const metrics: ScoreMetrics = {
    tier: "detect",
    labels_total: labelsTotal,
    labels_hit: labelsHit,
    findings_total: findingsTotal,
    true_positives: truePositives,
    false_positives: falsePositives,
    recall: isNegative ? null : labelsTotal === 0 ? 0 : labelsHit / labelsTotal,
    precision: findingsTotal === 0 ? null : truePositives / findingsTotal,
    severity_accuracy:
      isNegative || labelsHit === 0 ? null : severityCorrect / labelsHit,
    severity_correct: isNegative ? 0 : severityCorrect,
    severity_total: isNegative ? 0 : labelsHit,
  };

  return { labels, findings: findingResults, metrics };
}

/**
 * Confirmed tier — counterfactual `Attribution` ONLY, NO judge. Every finding
 * IS an exploit, keyed 1:1 to a `perExploit` entry by finding id; labels join by
 * `label.id`.
 */
export function scoreConfirmed(
  findings: Finding[],
  groundtruth: GroundTruth,
  attribution: Attribution,
): Scored {
  assertUniqueIds(groundtruth.vulns);
  const vulns = groundtruth.vulns;
  const labelSeverity = new Map<string, Severity>(
    vulns.map((label) => [label.id, label.severity]),
  );
  const findingById = new Map<string, Finding>(findings.map((f) => [f.id, f]));

  // label id -> the first attributed exploit id that covers it (for LabelResult).
  const labelHitBy = new Map<string, string>();
  for (const [exploitId, ids] of Object.entries(attribution.perExploit)) {
    for (const id of ids) if (!labelHitBy.has(id)) labelHitBy.set(id, exploitId);
  }

  const findingResults: FindingResult[] = Object.entries(
    attribution.perExploit,
  ).map(([exploitId, ids]) => {
    const attributed = ids.length > 0;
    const f = findingById.get(exploitId);
    return {
      id: exploitId,
      title: f?.title ?? exploitId,
      classification: attributed ? "TP" : "FP",
      matched_label: attributed ? ids[0] : null,
      confirmed: attributed,
    };
  });

  const labels: LabelResult[] = vulns.map((label) => {
    const hitBy = labelHitBy.get(label.id);
    if (!hitBy) {
      return {
        id: label.id,
        title: label.title,
        severity: label.severity,
        harm: label.harm ?? "state",
        status: "MISS",
        matched_finding: null,
        severity_correct: null,
      };
    }
    const f = findingById.get(hitBy);
    return {
      id: label.id,
      title: label.title,
      severity: label.severity,
      harm: label.harm ?? "state",
      status: "HIT",
      matched_finding: hitBy,
      severity_correct: f ? f.severity === label.severity : null,
    };
  });

  const labelsTotal = vulns.length;
  const exploitCarrying = Object.keys(attribution.perExploit).length;
  const attributed = Object.values(attribution.perExploit).filter(
    (h) => h.length > 0,
  ).length;
  const falsePositives = exploitCarrying - attributed;
  const labelsHit = attribution.confirmedLabels.length;

  // severity_accuracy: among attributed exploits, correct iff the exploit's
  // finding severity matches EVERY label it attributed to.
  let sevChecked = 0;
  let sevCorrect = 0;
  for (const [exploitId, ids] of Object.entries(attribution.perExploit)) {
    if (ids.length === 0) continue;
    const f = findingById.get(exploitId);
    if (!f) continue;
    sevChecked++;
    if (ids.every((id) => labelSeverity.get(id) === f.severity)) sevCorrect++;
  }

  const metrics: ScoreMetrics = {
    tier: "confirmed",
    labels_total: labelsTotal,
    labels_hit: labelsHit,
    findings_total: exploitCarrying,
    true_positives: attributed,
    false_positives: falsePositives,
    recall: labelsTotal === 0 ? 0 : labelsHit / labelsTotal,
    precision: exploitCarrying === 0 ? null : attributed / exploitCarrying,
    severity_accuracy: sevChecked === 0 ? null : sevCorrect / sevChecked,
    severity_correct: sevCorrect,
    severity_total: sevChecked,
  };

  return { labels, findings: findingResults, metrics };
}

/**
 * Tier dispatcher. `confirmable` selects the grader:
 *   confirmable=false -> detect (judge only)
 *   confirmable=true  -> confirmed (attribution only), requires `attribution`.
 * The judge is IGNORED in the confirmed tier and the attribution is IGNORED in
 * the detect tier — the two mechanisms never overlap.
 */
export async function scoreFindings(
  findings: Finding[],
  groundtruth: GroundTruth,
  judge: JudgeFn,
  confirmable: boolean = false,
  attribution?: Attribution,
): Promise<Scored> {
  if (!confirmable) return scoreDetect(findings, groundtruth, judge);
  if (!attribution) {
    throw new Error("confirmed tier requires an Attribution");
  }
  return scoreConfirmed(findings, groundtruth, attribution);
}
