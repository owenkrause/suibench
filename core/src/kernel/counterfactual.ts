// Counterfactual exploit attribution — pure set logic, zero I/O (runs are
// produced upstream by the effectful runner and handed here as plain values).
//
// Replaces the LLM judge on the exploitation axis with a deterministic question:
// which labels does an exploit witness against the VULNERABLE build (`base`),
// and — for each of those — does the label's OWN patch remove that witness? A
// base witness `L` is attributed iff `L` is in `base.witnesses` and `L` is NOT
// in `perLabel[L].witnesses`.
import type { Attribution, ExploitAttribution } from "./types.js";
import type { CheckResult } from "./checks.js";

export interface ExploitRun {
  readonly exploitId: string;
  /** The check result against the VULNERABLE build. */
  readonly base: CheckResult;
  /** perLabel[id]: the check result against patch_<id>.
   *  Only meaningful (and only populated) when base.witnesses is nonempty. */
  readonly perLabel: Readonly<Record<string, CheckResult>>;
}

/**
 * The kernel `Attribution` (perExploit / confirmedLabels) plus `dedupGroups`
 * (base-confirmed exploits sharing the same full attribution state). It is a
 * structural superset of `Attribution`, so it flows anywhere an `Attribution`
 * is expected.
 */
export interface AttributionResult extends Attribution {
  /** exploitIds grouped by identical attr signature (confirmed exploits only). */
  dedupGroups: string[][];
}

/** A label the counterfactual runs a patched variant for; keyed by `id`. */
export interface CounterfactualLabel {
  id: string;
}

/**
 * Runs an exploit against a variant of the target — the VULNERABLE build when
 * `patch=null`, else the given label's patched build — and reports the check
 * result. The real implementation (boot localnet, publish, run) is the
 * effectful runtime; this boundary keeps the orchestration below pure. The
 * orchestrator TRUSTS this result: it does not re-run `validateCheckResult`
 * or `runCheck` (that guard lives at the boundary that authored the result).
 */
export interface CounterfactualBoundary<L extends CounterfactualLabel> {
  runOnVariant: (
    entryDir: string,
    exploitPath: string,
    patch: L | null,
  ) => Promise<CheckResult>;
}

/**
 * The configured label universe must be well-formed before the boundary runs
 * anything: non-empty, unique ids. This is an orchestration invariant of
 * `runCounterfactuals`'s own configuration, not a defense on a check's
 * return value — that validation is `runCheck`'s job, once, at the boundary.
 */
function validateLabelUniverse<L extends CounterfactualLabel>(
  labels: readonly L[],
): void {
  const seen = new Set<string>();
  for (const label of labels) {
    if (label.id.length === 0) {
      throw new Error(
        `counterfactual label id must be a non-empty string, got ${JSON.stringify(label.id)}`,
      );
    }
    if (seen.has(label.id)) {
      throw new Error(`duplicate counterfactual label id "${label.id}"`);
    }
    seen.add(label.id);
  }
}

/**
 * Run one exploit against the vulnerable build and, if it witnesses any
 * mechanism there, against each label's patched build. An exploit that
 * witnesses nothing on the vulnerable build needs no per-label attribution,
 * so that case returns early with an empty `perLabel` — nothing to attribute,
 * no wasted variant runs. Otherwise every label patch is run diagnostically,
 * even for labels the base result didn't witness.
 */
export async function runCounterfactuals<L extends CounterfactualLabel>(
  entryDir: string,
  exploitId: string,
  exploitPath: string,
  labels: L[],
  boundary: CounterfactualBoundary<L>,
): Promise<ExploitRun> {
  validateLabelUniverse(labels);

  const base = await boundary.runOnVariant(entryDir, exploitPath, null);
  if (base.witnesses.length === 0) return { exploitId, base, perLabel: {} };

  const perLabel: Record<string, CheckResult> = {};
  await Promise.all(
    labels.map(async (label) => {
      perLabel[label.id] = await boundary.runOnVariant(
        entryDir,
        exploitPath,
        label,
      );
    }),
  );
  return { exploitId, base, perLabel };
}

/**
 * attr(exploit) = { L : L ∈ base.witnesses ∧ L ∉ perLabel[L].witnesses } — the
 * base witnesses whose own patch removed them. Purely set logic, no I/O, and
 * no check-result validation: `run`'s results were already validated once by
 * `runCheck` at the boundary that produced them.
 */
export function attribute(runs: ExploitRun[]): AttributionResult {
  const perExploit: Record<string, ExploitAttribution> = {};
  const confirmedLabelSet = new Set<string>();
  const signatureGroups = new Map<string, string[]>();
  const exploitIds = new Set<string>();

  for (const run of runs) {
    if (exploitIds.has(run.exploitId)) {
      throw new Error(`duplicate exploit id "${run.exploitId}"`);
    }
    exploitIds.add(run.exploitId);

    if (run.base.witnesses.length === 0) {
      perExploit[run.exploitId] = { kind: "refuted", labels: [] };
      continue;
    }

    const labels = run.base.witnesses
      .filter((label) => {
        const patched = run.perLabel[label];
        if (!patched) {
          throw new Error(`missing patch result for base witness "${label}"`);
        }
        return !patched.witnesses.includes(label);
      })
      .sort();
    const state: ExploitAttribution = labels.length > 0
      ? {
          kind: "attributed",
          labels: labels as [string, ...string[]],
        }
      : { kind: "unattributed", labels: [] };
    perExploit[run.exploitId] = state;

    for (const label of state.labels) confirmedLabelSet.add(label);

    const signature = `${state.kind}:${state.labels.join(",")}`;
    const group = signatureGroups.get(signature);
    if (group) group.push(run.exploitId);
    else signatureGroups.set(signature, [run.exploitId]);
  }

  return {
    perExploit,
    confirmedLabels: Array.from(confirmedLabelSet).sort(),
    dedupGroups: Array.from(signatureGroups.values()),
  };
}
