# suibench: integrity design

**1. Contamination is unrepresentable.** The model receives `SanitizedSource` — a branded type that only the `sanitize()` function can mint (`core/src/kernel/types.ts`). The `Observation` it grades carries no groundtruth field; `loadSource()` mounts only `Move.toml` + `sources/**.move` and structurally excludes `check.ts`, `exploits/`, `patches/`, `harness/`, and the label file (`suibench/src/dataset/entry.ts`). Decontamination is a type-system property, not a convention.

**2. Deterministic execution-based grading (the confirmer).** Confirmed-tier entries are graded by running the model's exploit on a fresh localnet, then evaluating the pre/post chain snapshots with no live-client access (`core/src/kernel/checks.ts`, `suibench/src/adapters/confirmer.ts`). No LLM sits in the grading path.

**3. Counterfactual attribution (N+1 grading).** A finding is credited to vulnerability _L_ only if the exploit confirms on the vulnerable code AND fails under _L_'s patch (`attribute = base ∧ ¬patchₗ`, `core/src/kernel/counterfactual.ts`). Each label ships a gold patch; the exploit is replayed against the base plus every patched variant, each in its own fresh boot (`suibench/src/adapters/counterfactual-boundary.ts`). An exploit with empty attribution (works on base, works under every patch) is a false positive.

**4. Perturbation / contamination testing (`verify:twins`, `--perturb`).** At eval time, semantics-preserving twins of each entry are regenerated (AST-level identifier renaming + comment stripping, seeded and reproducible), original vs. twins are graded, and `perturbation_gap = recall(original) − mean(recall(twins))` is reported as a memorization signal (`suibench/src/perturbation/`). An admissibility gate requires each twin to grade identically to its original before it counts. Twins are regenerated from a seed + content-hashed `transform_version`, never committed.

**5. Reproducibility manifest.** Every run records the `sui` version, Docker image ID, Node version, `@mysten/sui` version, git commit, and (in perturbation mode) the transform version + seed rule (`suibench/src/adapters/manifest.ts`).

**6. Two-tier scoring.** Confirmed-tier = deterministic counterfactual attribution; detect-tier = LLM-judge over findings↔labels (for entries without an execution oracle). Same metric schema, pooled micro/macro (`core/src/kernel/scorer.ts`).
