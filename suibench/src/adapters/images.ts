// Single source of truth for the per-role container images (spec §5.5). Each role
// gets its own image so the untrusted images carry no dataset and no harness dist/.
// Env-overridable per run; the node:slim gate image is introduced in Plan 2.
export const UNTRUSTED_IMAGE =
  process.env.SUIBENCH_UNTRUSTED_IMAGE ?? "suibench-untrusted-runtime";
export const CONFIRMER_IMAGE =
  process.env.SUIBENCH_CONFIRMER_IMAGE ?? "suibench-confirmer";
export const GATE_IMAGE = process.env.SUIBENCH_GATE_IMAGE ?? "suibench-gate";
