import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FileTrajectorySink } from "./trajectory-sink.js";

const roots: string[] = [];

async function freshDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "trajectory-sink-"));
  roots.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("FileTrajectorySink", () => {
  it("writes <dir>/<id>.json and round-trips the trajectory", async () => {
    const dir = await freshDir();
    const sink = new FileTrajectorySink(dir);
    const trajectory = { id: "t-0", env: { model: "m" }, messages: [{ role: "user" }] };

    await sink.save(trajectory);

    const text = await readFile(join(dir, "t-0.json"), "utf-8");
    expect(JSON.parse(text)).toEqual(trajectory);
  });
});
