// Counterfactual exploit attribution — pure set logic, zero I/O (runs are
// produced upstream by the effectful runner and handed here as plain values).
//
// Replaces the LLM judge on the exploitation axis with a deterministic question:
// does an exploit succeed against the VULNERABLE build (`base`), and — if so —
// does it STILL succeed once a given label's patch is overlaid? An exploit is
// attributed to bug `L` iff `base ∧ ¬perLabel[L]`.
import type { Attribution } from "./types.js";

export interface ExploitRun {
  exploitId: string;
  /** Did the exploit make the check pass on the VULNERABLE build? */
  base: boolean;
  /** perLabel[id]: did the exploit STILL pass under patch_<id>?
   *  Only meaningful (and only populated) when base=true. */
  perLabel: Record<string, boolean>;
}

/**
 * The kernel `Attribution` (perExploit / confirmedLabels) plus `dedupGroups`
 * (exploits sharing an attr signature). Structurally a superset of
 * `Attribution`, so it flows anywhere an `Attribution` is expected. False
 * positives are NOT a separate field: an empty `perExploit` entry IS the false
 * positive (base=false OR base=true-but-patch-invariant), so the scorer reads
 * them straight off `perExploit`.
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
 * `patch=null`, else the given label's patched build — and reports whether the
 * check passed. The real implementation (boot localnet, publish, run) is the
 * effectful runtime; this boundary keeps the orchestration below pure.
 */
export interface CounterfactualBoundary<L extends CounterfactualLabel> {
  runOnVariant: (
    entryDir: string,
    exploitPath: string,
    patch: L | null,
  ) => Promise<boolean>;
}

/**
 * Run one exploit against the vulnerable build and, if it succeeds there,
 * against each label's patched build. An exploit that fails on the vulnerable
 * build needs no per-label attribution, so that case returns early with an empty
 * `perLabel` — nothing to attribute, no wasted variant runs.
 */
export async function runCounterfactuals<L extends CounterfactualLabel>(
  entryDir: string,
  exploitId: string,
  exploitPath: string,
  labels: L[],
  boundary: CounterfactualBoundary<L>,
): Promise<ExploitRun> {
  const base = await boundary.runOnVariant(entryDir, exploitPath, null);
  if (!base) return { exploitId, base, perLabel: {} };

  const perLabel: Record<string, boolean> = {};
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
 * attr(exploit) = { L : exploit.base ∧ ¬exploit.perLabel[L] } — the labels whose
 * patch turned the exploit from success to failure. Purely set logic, no I/O.
 */
export function attribute(runs: ExploitRun[]): AttributionResult {
  const perExploit: Record<string, string[]> = {};
  const confirmedLabelSet = new Set<string>();
  const signatureGroups = new Map<string, string[]>();

  for (const run of runs) {
    if (!run.base) {
      // base=false: an empty attribution — a false positive, no per-label runs.
      perExploit[run.exploitId] = [];
      continue;
    }

    const attr = Object.keys(run.perLabel)
      .filter((label) => !run.perLabel[label])
      .sort();
    // base=true but attr empty (patch-invariant) is ALSO an empty entry — same
    // false-positive bucket as base=false, no separate field.
    perExploit[run.exploitId] = attr;

    for (const label of attr) confirmedLabelSet.add(label);

    const signature = attr.join(",");
    const group = signatureGroups.get(signature);
    if (group) group.push(run.exploitId);
    else signatureGroups.set(signature, [run.exploitId]);
  }

  return {
    perExploit,
    confirmedLabels: Array.from(confirmedLabelSet),
    dedupGroups: Array.from(signatureGroups.values()),
  };
}
