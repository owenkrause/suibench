// The Trajectory: the full transcript + score of one graded attempt, saved by
// the driver via `TrajectorySink` for later pre/post-grading review.
import type { RunEnv, RunScore, Exploit, Finding, MoveFile, PatchRunScore } from "core";
import type { AgentConversation, StopKind, CostTotals } from "core/runtime";

export interface Trajectory<Output, Score> {
  schemaVersion: 1;
  id: string;
  env: RunEnv;
  conversation: AgentConversation;
  stopReason: StopKind;
  cost: CostTotals;
  output: Output;
  score: Score;
}

/** Audit axis (exploitation/comprehension): parsed reports + the recall/precision score. */
export type AuditTrajectory = Trajectory<
  { exploits: Exploit[]; findings: Finding[] },
  RunScore
>;

/** Patch axis: the model's patched sources + the patch-rate score. */
export type PatchTrajectory = Trajectory<MoveFile[], PatchRunScore>;
