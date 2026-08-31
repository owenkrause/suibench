// Durable submission store. `Pool` is always injected (never constructed here
// except via createPool) so tests can pass a pg-mem pool with the same interface.
import { randomUUID } from "node:crypto";
import { Pool } from "pg";

export type SubmissionState = "queued" | "running" | "done" | "error";

export interface SubmissionRow {
  id: string;
  datasetVersion: string;
  chalId: string;
  payload: unknown;
  state: SubmissionState;
  score: unknown | null;
  error: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export function createPool(connectionString = process.env.DATABASE_URL): Pool {
  if (!connectionString) {
    throw new Error("createPool: DATABASE_URL is not set");
  }
  return new Pool({ connectionString });
}

// pg-mem (used in tests) doesn't support `timestamptz` or a `now()` column
// default, so we use `timestamp` and set `created_at`/`updated_at` explicitly
// from the application rather than relying on a DB-side default.
export async function initSchema(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS benchmark_submissions (
      id uuid primary key,
      dataset_version text not null,
      chal_id text not null,
      payload jsonb not null,
      state text not null,
      score jsonb,
      error text,
      created_at timestamp not null default now(),
      updated_at timestamp not null default now()
    )
  `);
}

export interface InsertSubmissionInput {
  datasetVersion: string;
  chalId: string;
  payload: unknown;
}

export async function insertSubmission(
  pool: Pool,
  { datasetVersion, chalId, payload }: InsertSubmissionInput,
): Promise<string> {
  const id = randomUUID();
  await pool.query(
    `INSERT INTO benchmark_submissions (id, dataset_version, chal_id, payload, state)
     VALUES ($1, $2, $3, $4, 'queued')`,
    [id, datasetVersion, chalId, JSON.stringify(payload)],
  );
  return id;
}

export interface UpdateSubmissionPatch {
  state?: SubmissionState;
  score?: unknown;
  error?: string;
}

export async function updateSubmission(
  pool: Pool,
  id: string,
  patch: UpdateSubmissionPatch,
): Promise<void> {
  const sets: string[] = [];
  const values: unknown[] = [];
  let i = 1;

  if (patch.state !== undefined) {
    sets.push(`state = $${i++}`);
    values.push(patch.state);
  }
  if (patch.score !== undefined) {
    sets.push(`score = $${i++}`);
    values.push(JSON.stringify(patch.score));
  }
  if (patch.error !== undefined) {
    sets.push(`error = $${i++}`);
    values.push(patch.error);
  }
  sets.push(`updated_at = now()`);

  values.push(id);
  await pool.query(
    `UPDATE benchmark_submissions SET ${sets.join(", ")} WHERE id = $${i}`,
    values,
  );
}

export async function getSubmission(pool: Pool, id: string): Promise<SubmissionRow | null> {
  const res = await pool.query(
    `SELECT id, dataset_version, chal_id, payload, state, score, error, created_at, updated_at
     FROM benchmark_submissions WHERE id = $1`,
    [id],
  );
  if (res.rows.length === 0) return null;
  const row = res.rows[0];
  return {
    id: row.id,
    datasetVersion: row.dataset_version,
    chalId: row.chal_id,
    payload: row.payload,
    state: row.state,
    score: row.score ?? null,
    error: row.error ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
