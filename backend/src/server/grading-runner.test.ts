import { newDb } from "pg-mem";
import { beforeEach, describe, expect, it } from "vitest";
import { CapacityError, createGradingRunner } from "./grading-runner.js";
import { getSubmission, initSchema } from "./db.js";
import { SlotPool } from "./slots.js";
import type { Pool } from "pg";
import type { DatasetEntry } from "suibench/dataset";
import type { SandboxManager } from "suibench/sandbox";

const PUBLISHED_VERSION = "deadbeef";
const ENTRY_ID = "chal_fake";

const fakeEntry = { id: ENTRY_ID, target: "fake", tier: "confirmed" } as unknown as DatasetEntry;
const fakeManager = {} as SandboxManager;

let pool: Pool;
let registry: Map<string, DatasetEntry>;

function buildRunner(grade: () => Promise<unknown>, maxInflight?: number) {
  return createGradingRunner({
    pool,
    slots: new SlotPool(1),
    manager: fakeManager,
    grade,
    registry,
    publishedVersion: PUBLISHED_VERSION,
    maxInflight,
  });
}

async function countRows(): Promise<number> {
  const res = await pool.query("SELECT count(*)::int AS c FROM benchmark_submissions");
  return res.rows[0].c;
}

beforeEach(async () => {
  const { Pool: MemPool } = newDb().adapters.createPg();
  pool = new MemPool();
  await initSchema(pool);
  registry = new Map([[ENTRY_ID, fakeEntry]]);
});

describe("createGradingRunner", () => {
  it("rejects a datasetVersion mismatch before writing any row", async () => {
    const runner = buildRunner(async () => ({}));
    await expect(
      runner.submitGrade({ datasetVersion: "wrong", entryId: ENTRY_ID, findings: [] }),
    ).rejects.toThrow(/datasetVersion mismatch/);
    expect(await countRows()).toBe(0);
  });

  it("rejects an unknown entryId before writing any row", async () => {
    const runner = buildRunner(async () => ({}));
    await expect(
      runner.submitGrade({ datasetVersion: PUBLISHED_VERSION, entryId: "chal_nope", findings: [] }),
    ).rejects.toThrow(/unknown entryId/);
    expect(await countRows()).toBe(0);
  });

  it("grades a valid submission to done with the canned score", async () => {
    const cannedScore = { metrics: { recall: 1 } };
    const runner = buildRunner(async () => cannedScore);

    const { jobId } = await runner.submitGrade({
      datasetVersion: PUBLISHED_VERSION,
      entryId: ENTRY_ID,
      findings: [],
    });

    // The background job races the caller's own follow-up read (it can already
    // be past "queued" into "running" by now) — assert only that it hasn't
    // reached a terminal state yet, i.e. grading really is async here.
    const preIdleRow = await getSubmission(pool, jobId);
    expect(["queued", "running"]).toContain(preIdleRow!.state);

    await runner.idle();

    const done = await runner.getGrade(jobId);
    expect(done!.state).toBe("done");
    expect(done!.score).toEqual(cannedScore);
  });

  it("rejects with CapacityError once inFlight is at maxInflight, without writing a row", async () => {
    let releaseBlocker: () => void;
    const blocker = new Promise<unknown>((resolve) => {
      releaseBlocker = () => resolve({});
    });
    const runner = buildRunner(() => blocker, 1);

    const first = await runner.submitGrade({
      datasetVersion: PUBLISHED_VERSION,
      entryId: ENTRY_ID,
      findings: [],
    });
    expect(first.jobId).toBeTruthy();
    expect(await countRows()).toBe(1);

    await expect(
      runner.submitGrade({ datasetVersion: PUBLISHED_VERSION, entryId: ENTRY_ID, findings: [] }),
    ).rejects.toThrow(CapacityError);
    // The rejected submission must not have inserted a second row.
    expect(await countRows()).toBe(1);

    // Unblock the first grade so the runner has no dangling in-flight work
    // left when the test ends.
    releaseBlocker!();
    await runner.idle();
  });

  it("records error state when grade() throws", async () => {
    const runner = buildRunner(async () => {
      throw new Error("boom: grading failed");
    });

    const { jobId } = await runner.submitGrade({
      datasetVersion: PUBLISHED_VERSION,
      entryId: ENTRY_ID,
      findings: [],
    });

    await runner.idle();

    const row = await runner.getGrade(jobId);
    expect(row!.state).toBe("error");
    expect(row!.error).toContain("boom: grading failed");
  });
});
