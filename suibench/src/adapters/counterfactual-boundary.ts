// A small composition factory. It does NOT reimplement the N+1 loop — that's the
// kernel's `runCounterfactuals` + `attribute`. It builds each variant's `Mount`
// (overlay the label's patch files; `null` = vulnerable build) and reduces the
// `ChainDelta` + attack-phase evidence through the entry `Check`, via the
// authoring guard `runCheck`, to a `CheckResult`. `baseProof` keeps each base
// run's proof for the `confirmed` verdict.
import type {
  Grader,
  GraderResult,
  Mount,
  MoveFile,
  ChainSnapshot,
  Check,
  CheckResult,
  CounterfactualBoundary,
  CounterfactualLabel,
} from "core";
import { sanitize, runCheck } from "core";
import { InfraError } from "./confirmer.js";

/** Attempts per variant boot before an infra failure is given up on. */
const INFRA_ATTEMPTS = 2;

/** A counterfactual label whose patch overlays files onto the vulnerable mount. */
export interface PatchedLabel extends CounterfactualLabel {
  /** Move source files to overlay (by in-package path) for this label's patch. */
  patchFiles: MoveFile[];
}

/**
 * Overlay a label's patch files onto the vulnerable `Mount`: a file whose path
 * matches an existing source REPLACES it (a real patch edits sources in place);
 * new paths are appended. `null` returns the vulnerable mount unchanged.
 */
export function variantMount(base: Mount, patch: PatchedLabel | null): Mount {
  if (!patch) return base;
  const byPath = new Map(base.files.map((f) => [f.path, f]));
  for (const f of patch.patchFiles) byPath.set(f.path, f);
  return sanitize([...byPath.values()]);
}

export interface BoundaryDeps {
  grader: Grader;
  vulnerableMount: Mount;
  readScript: (exploitPath: string) => MoveFile;
  check: Check;
  /** The entry's full manifest vulnerability-id universe — the `runCheck`
   *  authoring guard's allowed-witness set. Every manifest vuln id, not only
   *  the ids inferred from an outcome or the labels being patched. */
  allowedWitnessIds: readonly string[];
  /** Entry target, for the infra-failure log lines and the `runCheck` context. */
  label: string;
}

/** Grade one variant, retrying a transient `InfraError` (boot/publish/RPC) once
 *  before giving up. A given-up infra failure re-throws with the attempt count
 *  so the driver can record the entry as errored rather than crash the corpus. */
async function gradeWithRetry(
  deps: BoundaryDeps,
  mount: Mount,
  script: MoveFile,
): Promise<GraderResult> {
  let last: InfraError | undefined;
  for (let attempt = 1; attempt <= INFRA_ATTEMPTS; attempt++) {
    try {
      return await deps.grader.runOnMount(mount, script);
    } catch (err) {
      if (!(err instanceof InfraError)) throw err;
      last = err;
      console.error(
        `[bench] ${deps.label}: infra failure (attempt ${attempt}/${INFRA_ATTEMPTS}): ${err.message}`,
      );
    }
  }
  throw new InfraError(last!.message, INFRA_ATTEMPTS);
}

// `runCounterfactuals` drives `runOnVariant` (base, then per-label) — this factory
// owns none of that control flow. `baseProof` holds each base run's proof (iff
// the base witness set is nonempty) for the `confirmed` verdict.
export function counterfactualBoundary(deps: BoundaryDeps): {
  boundary: CounterfactualBoundary<PatchedLabel>;
  baseProof: Map<string, ChainSnapshot | null>;
} {
  const baseProof = new Map<string, ChainSnapshot | null>();

  const boundary: CounterfactualBoundary<PatchedLabel> = {
    runOnVariant: async (
      _entryDir: string,
      exploitPath: string,
      patch: PatchedLabel | null,
    ): Promise<CheckResult> => {
      const mount = variantMount(deps.vulnerableMount, patch);
      const script = deps.readScript(exploitPath);
      // The grader boots the localnet + runs setup, so it owns the ChainDelta
      // (pre = post-setup baseline, post = post-attack), the per-boot
      // CheckParams (freshly-published packageId + funded addresses), AND the
      // attack-phase CheckEvidence — all three are passed through `runCheck`
      // unchanged, the ONLY helper allowed to invoke `deps.check`.
      const { delta, params, evidence } = await gradeWithRetry(deps, mount, script);
      const result = runCheck(
        deps.check,
        deps.allowedWitnessIds,
        delta,
        params,
        evidence,
        `${deps.label}/${patch?.id ?? "base"}`,
      );
      if (patch === null) {
        baseProof.set(exploitPath, result.witnesses.length > 0 ? delta.post : null);
      }
      return result;
    },
  };

  return { boundary, baseProof };
}
