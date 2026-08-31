import { randomUUID } from "node:crypto";
import { newDb } from "pg-mem";
import { beforeEach, describe, expect, it } from "vitest";
import { getSubmission, initSchema, insertSubmission, updateSubmission } from "./db.js";
import type { Pool } from "pg";

let pool: Pool;

beforeEach(async () => {
  const { Pool: MemPool } = newDb().adapters.createPg();
  pool = new MemPool();
  await initSchema(pool);
});

describe("db", () => {
  it("inserts a submission and reads it back queued", async () => {
    const id = await insertSubmission(pool, {
      datasetVersion: "abc123",
      chalId: "chal_deadbeef",
      payload: { foo: "bar" },
    });
    const row = await getSubmission(pool, id);
    expect(row).not.toBeNull();
    expect(row!.state).toBe("queued");
    expect(row!.payload).toEqual({ foo: "bar" });
    expect(row!.datasetVersion).toBe("abc123");
    expect(row!.chalId).toBe("chal_deadbeef");
    expect(row!.score).toBeNull();
    expect(row!.error).toBeNull();
  });

  it("updates state and score, and reflects them on read", async () => {
    const id = await insertSubmission(pool, {
      datasetVersion: "abc123",
      chalId: "chal_deadbeef",
      payload: { foo: "bar" },
    });
    await updateSubmission(pool, id, { state: "done", score: { passed: true } });
    const row = await getSubmission(pool, id);
    expect(row!.state).toBe("done");
    expect(row!.score).toEqual({ passed: true });
  });

  it("returns null for an unknown id", async () => {
    const row = await getSubmission(pool, randomUUID());
    expect(row).toBeNull();
  });
});
