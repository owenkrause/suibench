import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { lazyJudge, parseArgs } from "./cli.js";

describe("parseArgs", () => {
  it("applies production-safe defaults", () => {
    const args = parseArgs([]);
    expect(args).toMatchObject({
      axis: "exploitation",
      harness: "harnessed",
      k: 1,
      concurrency: 3,
      maxTurns: 60,
      perturb: false,
      twinsPerEntry: 3,
    });
  });

  it("parses --perturb and --twins-per-entry", () => {
    const args = parseArgs(["--perturb", "--twins-per-entry", "5"]);
    expect(args).toMatchObject({ perturb: true, twinsPerEntry: 5 });
  });

  it.each([
    ["--k", "0"],
    ["--k", "Infinity"],
    ["--concurrency", "0"],
    ["--concurrency", "nope"],
    ["--max-turns", "0"],
    ["--max-turns", "1.5"],
  ])("rejects an unsafe numeric bound: %s %s", (flag, value) => {
    expect(() => parseArgs([flag, value])).toThrow(/positive integer/);
  });

  it("rejects typos and missing values instead of silently using defaults", () => {
    expect(() => parseArgs(["--concurreny", "2"])).toThrow(/unknown option/);
    expect(() => parseArgs(["--concurrency"])).toThrow(/requires a value/);
  });

  it("accepts static + exploitation (raw baseline: blind exploit, confirmer-graded)", () => {
    const args = parseArgs(["--axis", "exploitation", "--harness", "static"]);
    expect(args.axis).toBe("exploitation");
    expect(args.harness).toBe("static");
  });

  it("validates effort against the selected model", () => {
    expect(() =>
      parseArgs(["--model", "gpt-5", "--effort", "max"]),
    ).toThrow(/does not support/);
  });

  it("classifies lazy judge setup failure as a model operation error", async () => {
    const judge = lazyJudge("claude-opus-4-8", () => {
      throw new Error("missing judge credential");
    });
    await expect(judge(
      {
        id: "finding",
        module: "vault",
        severity: "high",
        title: "finding",
        description: "description",
      },
      [{
        id: "label",
        module: "vault",
        severity: "high",
        title: "label",
        root_cause: "root cause",
      }],
    )).rejects.toMatchObject({
      name: "AgentError",
      message: expect.stringMatching(/judge setup failed/),
    });
  });

  it("runs when invoked through an installed-bin symlink", () => {
    const dir = mkdtempSync(join(tmpdir(), "suibench-cli-"));
    const link = join(dir, "suibench.ts");
    symlinkSync(resolve(import.meta.dirname, "cli.ts"), link);
    try {
      const result = spawnSync(
        process.execPath,
        ["--import", "tsx", link, "--definitely-invalid", "value"],
        {
          cwd: resolve(import.meta.dirname, "../.."),
          encoding: "utf-8",
        },
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toMatch(/unknown option/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
