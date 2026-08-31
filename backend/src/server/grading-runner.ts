// Ties the DB store, the slot pool, and the dataset registry to suibench's
// `gradeSubmission` facade. `createGradingRunner` is the pure, DB/slot-injected
// factory (unit-tested with a pg-mem pool + a fake `grade`, no Docker); the
// lazy default below is what the routes actually import — it must NOT touch
// `createPool()`/Docker at import time, or the build (no DATABASE_URL) breaks.
import type { Pool } from "pg";
import { getSubmission, initSchema, insertSubmission, updateSubmission, createPool } from "./db.js";
import type { SubmissionRow } from "./db.js";
import { SlotPool } from "./slots.js";
import { PUBLISHED_VERSION, registry } from "./version.js";
import { gradeSubmission } from "suibench/submission";
import type { SubmittedFinding } from "suibench/submission";
import { SandboxManager } from "suibench/sandbox";
import type { DatasetEntry } from "suibench/dataset";

export interface GradingRunnerDeps {
  pool: Pool;
  slots: SlotPool;
  manager: SandboxManager;
  grade: (entry: DatasetEntry, findings: SubmittedFinding[], manager: SandboxManager) => Promise<unknown>;
  registry: Map<string, DatasetEntry>;
  publishedVersion: string;
  /** Admission cap on queued+running submissions (see `inFlight`). @default 100 */
  maxInflight?: number;
}

// Thrown by submitGrade when `inFlight` is already at `maxInflight` — the
// caller (the API route) maps this to 429, distinct from the 400s used for
// request-shape validation failures.
export class CapacityError extends Error {}

export interface SubmitGradeRequest {
  datasetVersion: string;
  entryId: string;
  findings: SubmittedFinding[];
}

export interface GradingRunner {
  submitGrade(req: SubmitGradeRequest): Promise<{ jobId: string }>;
  getGrade(id: string): Promise<SubmissionRow | null>;
  idle(): Promise<void>;
}

export function createGradingRunner(deps: GradingRunnerDeps): GradingRunner {
  const inFlight = new Set<Promise<void>>();
  const maxInflight = deps.maxInflight ?? 100;

  async function submitGrade({ datasetVersion, entryId, findings }: SubmitGradeRequest): Promise<{ jobId: string }> {
    if (datasetVersion !== deps.publishedVersion) {
      throw new Error(`datasetVersion mismatch (published: ${deps.publishedVersion})`);
    }
    const entry = deps.registry.get(entryId);
    if (!entry) {
      throw new Error(`unknown entryId "${entryId}"`);
    }
    if (inFlight.size >= maxInflight) {
      throw new CapacityError("server at capacity, retry later");
    }

    const id = await insertSubmission(deps.pool, { datasetVersion, chalId: entryId, payload: { findings } });

    const p = (async () => {
      try {
        // v1: the slot pool bounds concurrent SUBMISSIONS (matching suibench's
        // --concurrency outer-unit model), not the leaf Docker topologies.
        // Findings grade sequentially in gradeExploitation, so per-submission
        // peak is 1+#labels localnets; total peak ≈ N×(1+maxLabels) with
        // N = BENCHMARK_GRADE_SLOTS (keep low). A true leaf-level cap (a
        // permit per Confirmer.runOnMount) is deferred — revisit before
        // scaling past a few trusted submitters.
        const score = await deps.slots.withSlot(async () => {
          await updateSubmission(deps.pool, id, { state: "running" });
          return deps.grade(entry, findings, deps.manager);
        });
        await updateSubmission(deps.pool, id, { state: "done", score });
      } catch (err) {
        await updateSubmission(deps.pool, id, {
          state: "error",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    })();
    // If the terminal state write itself fails (e.g. DB down while recording
    // done/error), surface it loudly instead of swallowing it — no retry, no
    // timeout. The row may be left non-terminal, but the failure is logged, not
    // hidden. `tracked` still resolves (never rejects) so idle()/inFlight stay sane.
    const tracked = p.catch((err: unknown) => {
      console.error(`[grading] failed to persist terminal state for job ${id}:`, err);
    });
    inFlight.add(tracked);
    tracked.finally(() => inFlight.delete(tracked));

    return { jobId: id };
  }

  async function getGrade(id: string): Promise<SubmissionRow | null> {
    return getSubmission(deps.pool, id);
  }

  async function idle(): Promise<void> {
    await Promise.all([...inFlight]);
  }

  return { submitGrade, getGrade, idle };
}

// --- Lazy default (what the routes import) ----------------------------------

let _pool: Pool | undefined;
let _manager: SandboxManager | undefined;
let _runner: GradingRunner | undefined;

function ensure(): GradingRunner {
  if (!_runner) {
    _pool = createPool(); // throws if DATABASE_URL unset — only when actually used
    _manager = new SandboxManager();
    _runner = createGradingRunner({
      pool: _pool,
      slots: new SlotPool(Number(process.env.BENCHMARK_GRADE_SLOTS ?? 2)),
      manager: _manager,
      grade: gradeSubmission,
      registry: registry(),
      publishedVersion: PUBLISHED_VERSION,
      maxInflight: Number(process.env.BENCHMARK_MAX_INFLIGHT ?? 100),
    });
  }
  return _runner;
}

export async function initGrading(): Promise<void> {
  ensure();
  await initSchema(_pool!);
}

export const submitGrade = (req: SubmitGradeRequest): Promise<{ jobId: string }> => ensure().submitGrade(req);

export const getGrade = (id: string): Promise<SubmissionRow | null> => ensure().getGrade(id);

export async function teardownGrading(): Promise<void> {
  await _manager?.teardownAll?.();
  await _pool?.end?.();
}
