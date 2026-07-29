// Patch-mode grading — the pure decision, per vulnerability.
//
// The model is HANDED the known vulnerabilities and returns corrected source.
// ONE patched build is graded against EACH labeled vuln:
//
//     patch_correct(V) = compiles ∧ ¬(V's exploit still succeeds) ∧ functional_passes
//
// `compile` and `functional` are shared gates over the whole patched package;
// only the exploit re-run is per-vuln. The three phases are an INJECTED boundary,
// so this decision is pure (no Docker/sui/fs). Overlaying the patch and wiring
// the real boundary is effectful and lives outside the kernel.

export interface CompileResult {
  compiles: boolean;
  /** Build output on failure (for the trace); empty on success. */
  error?: string;
}

export interface ExploitReRun {
  /** true ⇒ the exploit STILL succeeds on the patched build (bug not fixed). */
  confirmed: boolean;
  error?: string;
}

export interface FunctionalRun {
  passed: boolean;
  error?: string;
}

/**
 * The injectable boundary the patch grader drives. It closes over the entry +
 * the model's patched sources (built effectfully in the adapter), so the pure
 * decision passes only what varies: which vuln's exploit to re-run.
 * `confirmExploit` re-runs ONE vuln's exploit; `compile`/`runFunctional` grade
 * the whole patched package.
 */
export interface PatchGraderBoundary {
  compile: () => Promise<CompileResult>;
  confirmExploit: (vulnId: string) => Promise<ExploitReRun>;
  runFunctional: () => Promise<FunctionalRun>;
}

/** One vuln's verdict under the patch. */
export interface VulnPatchResult {
  vulnId: string;
  /** true ⇒ this vuln's exploit still succeeds against the patched build. */
  exploit_still_succeeds: boolean;
  /** compiles ∧ ¬exploit_still_succeeds ∧ functional_passes. */
  patch_correct: boolean;
  /** Blocking reason for this vuln (exploit-not-fixed or shared functional break). */
  error?: string;
}

export interface PatchGrade {
  target: string;
  compiles: boolean;
  functional_passes: boolean;
  perVuln: VulnPatchResult[];
  /** # vulns whose patch is correct. */
  patched: number;
  total: number;
  /** First blocking SHARED reason (compile / functional), for the trace. */
  error?: string;
}

/**
 * The pure grading decision. A patch that doesn't compile is never published, so
 * nothing downstream runs and every vuln fails. Otherwise: re-run each vuln's
 * exploit (must now fail) and run the legit `functional` flow once (must pass).
 * `patch_correct(V) = compiles ∧ ¬exploit_still_succeeds(V) ∧ functional_passes`.
 */
export async function gradePatch(
  target: string,
  vulnIds: string[],
  boundary: PatchGraderBoundary,
): Promise<PatchGrade> {
  const compile = await boundary.compile();
  if (!compile.compiles) {
    const err = `patch does not compile: ${compile.error ?? "sui move build failed"}`;
    return {
      target,
      compiles: false,
      functional_passes: false,
      perVuln: vulnIds.map((vulnId) => ({
        vulnId,
        exploit_still_succeeds: false,
        patch_correct: false,
        error: err,
      })),
      patched: 0,
      total: vulnIds.length,
      error: err,
    };
  }

  // Per-vuln exploit re-runs, then the shared functional gate once.
  const reruns: ExploitReRun[] = [];
  for (const vulnId of vulnIds) {
    reruns.push(await boundary.confirmExploit(vulnId));
  }
  const functional = await boundary.runFunctional();
  const functional_passes = functional.passed;

  const perVuln: VulnPatchResult[] = vulnIds.map((vulnId, i) => {
    const exploit_still_succeeds = reruns[i].confirmed;
    const patch_correct = !exploit_still_succeeds && functional_passes;
    const error = exploit_still_succeeds
      ? "exploit still succeeds against the patched package (vulnerability not fixed)"
      : !functional_passes
        ? `functional check failed (legit behavior broken): ${functional.error ?? "functional aborted"}`
        : undefined;
    return { vulnId, exploit_still_succeeds, patch_correct, error };
  });

  return {
    target,
    compiles: true,
    functional_passes,
    perVuln,
    patched: perVuln.filter((v) => v.patch_correct).length,
    total: vulnIds.length,
    error: functional_passes
      ? undefined
      : `functional check failed on the patched package (legit behavior broken): ${functional.error ?? "functional aborted"}`,
  };
}

// --- Patch score hierarchy (runs → entry → corpus) ---------------------------
// Patch mode's own scorecard — separate from the recall/precision `CorpusScore`,
// because the unit is vulns-correctly-patched, not labels-found. The rate is
// patched vulns / total vulns.

/** One patch run of one entry — the `PatchGrade` is the leaf. */
export type PatchRunScore = PatchGrade;

/** pass@k rollup over K patch runs of one entry (only present when k > 1). */
export interface PatchPassK {
  runs: PatchRunScore[];
  /** fraction of runs that patched EVERY vuln. */
  passRate: number;
  /** mean patched/total across runs. */
  meanRate: number;
}

export interface PatchEntryScore {
  target: string;
  /** representative run (best of k). */
  run: PatchRunScore;
  passk?: PatchPassK;
}

/** An entry the grader could not patch-grade (infra failure), kept OUT of the
 *  rate so it never counts as unpatched. */
export interface PatchErroredEntry {
  target: string;
  error: string;
  attempts: number;
}

export interface PatchCorpusScore {
  /** false iff any entry errored — the rate covers scored entries only. */
  complete: boolean;
  scored: number;
  errored: number;
  /** patched vulns / total vulns across scored entries; null if no vulns. */
  patchRate: number | null;
  patchedVulns: number;
  totalVulns: number;
  entries: PatchEntryScore[];
  erroredEntries: PatchErroredEntry[];
}

const patchedRate = (r: PatchRunScore): number =>
  r.total === 0 ? 0 : r.patched / r.total;

/** pass@k fold: the run that patched the most vulns. */
export const bestPatchRun = (runs: PatchRunScore[]): PatchRunScore =>
  runs.reduce((best, r) => (r.patched > best.patched ? r : best));

/** runs → entry (pass@k). k=1 is a single run (no `passk`). */
export async function passKPatch(
  k: number,
  target: string,
  task: () => Promise<PatchRunScore>,
): Promise<PatchEntryScore> {
  if (k <= 1) return { target, run: await task() };
  const runs: PatchRunScore[] = [];
  for (let i = 0; i < k; i++) runs.push(await task());
  const fully = runs.filter((r) => r.total > 0 && r.patched === r.total).length;
  const meanRate = runs.reduce((s, r) => s + patchedRate(r), 0) / runs.length;
  return {
    target,
    run: bestPatchRun(runs),
    passk: { runs, passRate: fully / runs.length, meanRate },
  };
}

/** entries → corpus. Micro rate: pool patched/total across entries. */
export function aggregatePatchCorpus(
  entries: PatchEntryScore[],
  erroredEntries: PatchErroredEntry[] = [],
): PatchCorpusScore {
  const patchedVulns = entries.reduce((s, e) => s + e.run.patched, 0);
  const totalVulns = entries.reduce((s, e) => s + e.run.total, 0);
  return {
    complete: erroredEntries.length === 0,
    scored: entries.length,
    errored: erroredEntries.length,
    patchRate: totalVulns === 0 ? null : patchedVulns / totalVulns,
    patchedVulns,
    totalVulns,
    entries,
    erroredEntries,
  };
}
