// SELF-TEST HARNESS (Task 4) — the MINIMAL run-and-grade wiring that exercises
// the reward-hacking controls. This is NOT the real agent loop (Task 5) nor the
// real Sandbox/Grader adapters (Task 6); those replace the fakes below. It does
// exactly enough to prove: a policy's reports flow through the injected `Grader`
// + `Check` counterfactual into `attribute()` + `scoreConfirmed()`, and that a
// policy can never mint on-chain proof of its own.
import {
  type Policy,
  type Grader,
  type Observation,
  type Exploit,
  type Finding,
  type Verdict,
  type RunScore,
  type ChainSnapshot,
  type Check,
  type GroundTruth,
  type VulnLabel,
  type CounterfactualBoundary,
  type CounterfactualLabel,
  type ExploitRun,
  type SanitizedSource,
  type Mount,
  runCounterfactuals,
  attribute,
  scoreConfirmed,
  confirmed,
  falsePositive,
  sanitize,
} from "core";

/**
 * The mount marker a patched variant carries. Real Task-6 adapters overlay the
 * label's patch FILES onto the sanitized source; here the harness appends a
 * marker file so the fake `Grader` — which has ONLY the mount + script, exactly
 * like the port — can tell which variant it's grading. The vulnerable build
 * carries no marker.
 */
export const PATCH_MARKER = "__patch__/id";

/** Read the patch id a variant mount encodes, or null for the vulnerable build. */
export function mountPatchId(mount: Mount): string | null {
  const marker = mount.files.find((f) => f.path === PATCH_MARKER);
  return marker ? marker.contents : null;
}

/**
 * One labeled bug the counterfactual runs a patched variant for. `id` is the
 * counterfactual key; `label` is the groundtruth row it stands for.
 */
export interface HarnessLabel extends CounterfactualLabel {
  label: VulnLabel;
}

/** Everything the harness grades one entry against. The check's `CheckParams`
 *  are NOT here — the grader produces them per-boot and hands them back with the
 *  delta (see the `Grader` port), matching the real Confirmer. */
export interface Entry {
  target: string;
  groundtruth: GroundTruth;
  labels: HarnessLabel[];
  check: Check;
  observation: Observation;
}

/**
 * Drive the policy until it stops reporting. Minimal by design: repeatedly call
 * `act`, collecting `report_exploit`, and stop on the first non-report action
 * (the policy's "done" sentinel) or the step cap. The model tests its own
 * hypotheses in the loop and only reports findings it can exploit.
 */
export async function collectReports(
  policy: Policy,
  observation: Observation,
  maxSteps = 32,
): Promise<{ exploits: Exploit[]; findings: Finding[] }> {
  const exploits: Exploit[] = [];
  const findings: Finding[] = [];
  for (let i = 0; i < maxSteps; i++) {
    const action = await policy.act(observation);
    if (action.kind === "report_exploit") {
      exploits.push(action.exploit);
      findings.push(action.exploit.finding);
    } else {
      break; // any non-report action is the terminal sentinel here
    }
  }
  return { exploits, findings };
}

/**
 * Compose the two effect seams into the pure kernel's `CounterfactualBoundary`:
 * the injected `Grader` PRODUCES each variant's committed `ChainDelta` (it boots
 * the localnet + runs setup, so it owns the pre/post pair), and the entry's
 * `Check` REDUCES that delta to the boolean the counterfactual set-logic
 * consumes. A patch (label) selects which variant the Grader runs; `null` is the
 * vulnerable build.
 */
function boundaryFromGraderAndCheck(entry: Entry, grader: Grader): {
  boundaryFor: (exploit: Exploit) => CounterfactualBoundary<HarnessLabel>;
} {
  return {
    boundaryFor: (exploit: Exploit) => ({
      runOnVariant: async (
        _entryDir: string,
        _exploitPath: string,
        patch: HarnessLabel | null,
      ): Promise<boolean> => {
        const mount = variantMount(entry, patch);
        const { delta, params } = await grader.runOnMount(mount, exploit.script);
        return entry.check(delta, params);
      },
    }),
  };
}

/**
 * The `SanitizedSource` mount for a variant. The vulnerable build is the entry's
 * own source; a patched variant is the same source plus a `PATCH_MARKER` file
 * naming the label (a stand-in for real overlaid patch files). The grader sees
 * ONLY this mount — no out-of-band patch channel — matching the `Grader` port.
 */
function variantMount(entry: Entry, patch: HarnessLabel | null): SanitizedSource {
  const base = entry.observation.source;
  if (!patch) return base;
  return sanitize([
    ...base.files,
    { path: PATCH_MARKER, contents: patch.id },
  ]);
}

export interface RunResult {
  score: RunScore;
  verdicts: Verdict[];
}

/**
 * Run one policy against one entry through the injected `Grader`, and grade it
 * with the confirmed-tier attribution. Returns the `RunScore` plus a `Verdict`
 * per collected exploit. A confirmed verdict is minted ONLY from a
 * Grader-produced snapshot (via the check-passing base run); an exploit that
 * doesn't attribute yields `false_positive` — the policy has no other channel to
 * claim success.
 */
export async function runAndGrade(
  policy: Policy,
  grader: Grader,
  entry: Entry,
): Promise<RunResult> {
  const { exploits, findings } = await collectReports(
    policy,
    entry.observation,
  );

  const { boundaryFor } = boundaryFromGraderAndCheck(entry, grader);

  const runs: ExploitRun[] = [];
  const baseProof = new Map<string, ChainSnapshot | null>();
  for (const exploit of exploits) {
    const id = exploit.finding.id;
    const boundary = boundaryFor(exploit);
    const basePost = await captureBase(entry, grader, exploit);
    baseProof.set(id, basePost);
    const run = await runCounterfactuals(
      entry.target,
      id,
      exploit.script.path,
      entry.labels,
      boundary,
    );
    runs.push(run);
  }

  const attribution = attribute(runs);
  const score = scoreConfirmed(findings, entry.groundtruth, attribution);

  const verdicts: Verdict[] = exploits.map((exploit) => {
    const id = exploit.finding.id;
    const attributed = (attribution.perExploit[id] ?? []).length > 0;
    if (attributed) {
      const proof = baseProof.get(id);
      // an attributed exploit passed its base run, so a proof snapshot exists.
      return confirmed(exploit, proof!);
    }
    return falsePositive(
      `exploit ${id} did not attribute to any label (base failed or patch-invariant)`,
    );
  });

  return { score, verdicts };
}

/** The base (vulnerable-build) snapshot for an exploit — the confirmed proof.
 *  The grader owns the delta (pre = post-setup baseline, post = post-attack);
 *  the proof is `delta.post`. */
async function captureBase(
  entry: Entry,
  grader: Grader,
  exploit: Exploit,
): Promise<ChainSnapshot | null> {
  const mount = variantMount(entry, null);
  const { delta, params } = await grader.runOnMount(mount, exploit.script);
  return entry.check(delta, params) ? delta.post : null;
}
