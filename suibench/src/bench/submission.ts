// The submission facade — grades submitter-supplied reports through the SAME
// exploitation path an agent run uses (`runEntryOnce`), by injecting a `runFor`
// that returns the submitted reports verbatim (no finding phase to run) and a
// sink that persists nothing. This is the service-safe entry point for a web
// submission handler — it must never call `runEntryOnce` raw.
import type { DatasetEntry } from "../dataset/index.js";
import { runEntryOnce, type BenchDeps } from "./driver.js";
import { Confirmer } from "../adapters/confirmer.js";
import type { SandboxManager } from "../adapters/sandbox.js";
import type { Exploit, Finding, MoveFile, RunEnv, RunScore } from "core";

export type SubmittedFinding = { finding: Finding; script: MoveFile };

// Neutral values for the fields the exploitation axis path never reads (no
// model runs — `runFor` below just echoes the submitted reports).
const SUBMISSION_ENV: RunEnv = { model: "submission", effort: "none" };

const noopSink = { save: async () => {} };

export async function gradeSubmission(
  entry: DatasetEntry,
  findings: SubmittedFinding[],
  manager: SandboxManager,
): Promise<RunScore> {
  const exploits: Exploit[] = findings.map((f) => ({ finding: f.finding, script: f.script }));
  const bare: Finding[] = findings.map((f) => f.finding);

  const deps: BenchDeps = {
    runFor: async () => ({
      exploits,
      findings: bare,
      conversation: { systemPrompt: "", messages: [] },
      stopReason: "end_turn",
      cost: { inputTokens: 0, outputTokens: 0, turns: 0 },
    }),
    graderFor: (e) => new Confirmer(manager, e.harness),
    sink: noopSink,
  };

  return runEntryOnce(
    entry,
    { harness: "harnessed", axis: "exploitation", env: SUBMISSION_ENV },
    deps,
  );
}
