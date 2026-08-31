import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { benchPerturb } from "./perturb-driver.js";
import type { BenchDeps, RunConfig } from "./driver.js";
import type { Exploit, Grader, Mount, MoveFile, ChainSnapshot } from "core";
import { AgentError, type CostMeter, type CostTotals, type TrajectorySink, type Usage } from "core/runtime";

// Twin dirs materialize with a `check.ts` that bare-imports "core" — loadCheck
// dynamic-imports that file, so it must resolve "core" via node_modules
// resolution, which only walks up from a path INSIDE the workspace tree. A
// dump dir under node:os tmpdir() (outside the tree) can't resolve it.
// `.suibench/` is the established, already-gitignored run-output scratch dir.
const SCRATCH_ROOT = resolve(import.meta.dirname, "../../.suibench");

// A confirmed-tier dataset entry that exists on disk (capability_leak) drives the
// read/generate path. The fake grader reads the MOUNTED source (post-rename twin
// or comment-stripped original — both survive the fix-marker string) to decide
// vulnerable vs. patched, so both sides of the gap score identically.
const config: RunConfig = { harness: "harnessed", axis: "exploitation", env: { model: "none", effort: "low" }, k: 1 };

const PKG = "0xpkg";
const ATTACKER = "0xattacker";
const ADMIN = "0xadmin";

function emptySnapshot(): ChainSnapshot {
  return { balances: { byAddress: {} }, objects: { ownerOf: {}, byId: {} } };
}

function vulnerableSnapshot(capType: string): ChainSnapshot {
  return {
    balances: { byAddress: {} },
    objects: {
      ownerOf: { cap1: ATTACKER, cap0: ADMIN },
      byId: {
        cap1: { owner: { AddressOwner: ATTACKER }, type: capType, fields: {} },
        cap0: { owner: { AddressOwner: ADMIN }, type: capType, fields: {} },
      },
    },
  };
}

// Both `generateTwin` (rename) and `stripEntry` (comment-strip-only) preserve the
// patch's fix text, so gating on it is robust across original vs. twin mounts.
function isPatched(mount: Mount): boolean {
  return mount.files.some((f) => f.contents.includes("abort"));
}

// The mounted source's module/cap-type names get renamed per-twin, so the fake
// grader can't hardcode `vault::AdminCap` — it reads the module name and the
// `has key, store` struct (the AdminCap-equivalent) straight off the mount,
// mirroring how a real grader would read the freshly-published package.
function capType(mount: Mount): string {
  const src = mount.files.find((f) => f.path === "sources/vault.move")!.contents;
  const mod = src.match(/module\s+\w+::(\w+)\s*\{/)![1];
  const cap = src.match(/struct\s+(\w+)\s+has\s+key,\s*store\s*\{/)![1];
  return `${PKG}::${mod}::${cap}`;
}

function fakeGrader(): Grader {
  return {
    async runOnMount(mount: Mount, _script: MoveFile) {
      const post = isPatched(mount) ? emptySnapshot() : vulnerableSnapshot(capType(mount));
      return {
        delta: { pre: emptySnapshot(), post },
        params: { packageId: PKG, attackerAddress: ATTACKER, adminAddress: ADMIN },
        evidence: { attackTransactions: [] },
      };
    },
  };
}

describe("benchPerturb", () => {
  let dump: string | undefined;

  afterEach(() => {
    if (dump) rmSync(dump, { recursive: true, force: true });
    dump = undefined;
  });

  it("regenerates K twins, dumps them, and computes a zero gap when grading matches", async () => {
    mkdirSync(SCRATCH_ROOT, { recursive: true });
    dump = mkdtempSync(join(SCRATCH_ROOT, "twins-"));
    const noopSink: TrajectorySink = { save: async () => {} };
    const deps: BenchDeps = {
      runFor: async () => {
        const exploit = {
          finding: { id: "admincap-leak", module: "vault", severity: "critical", title: "t", description: "d" },
          script: { path: "x.mts", contents: "attack" },
        } satisfies Exploit;
        return {
          exploits: [exploit],
          findings: [exploit.finding],
          conversation: { systemPrompt: "sys", messages: [] },
          stopReason: "end_turn" as const,
          cost: { inputTokens: 0, outputTokens: 0, turns: 0 },
        };
      },
      graderFor: () => fakeGrader(),
      sink: noopSink,
    };
    const report = await benchPerturb(
      [resolve(import.meta.dirname, "../../dataset/capability_leak")],
      config,
      deps,
      { twinsPerEntry: 2, twinDumpDir: dump },
    );
    expect(report.perEntry).toHaveLength(1);
    expect(readdirSync(join(dump, "capability_leak__0")).length).toBeGreaterThan(0);
    expect(readdirSync(join(dump, "capability_leak__1")).length).toBeGreaterThan(0);
    expect(report.perEntry[0].perturbation_gap).toBe(0);
    expect(report.macro_gap).toBe(0);

    // Symmetric strip: the scored-original dir (__orig) exists and is comment-free.
    const origVault = readFileSync(join(dump, "capability_leak__orig", "sources", "vault.move"), "utf-8");
    expect(origVault).not.toContain("//");
    expect(origVault).not.toContain("/*");
  });

  it("aggregates original and twin policy costs under the original target", async () => {
    mkdirSync(SCRATCH_ROOT, { recursive: true });
    dump = mkdtempSync(join(SCRATCH_ROOT, "twins-"));
    const receivedMeters: Array<CostMeter | undefined> = [];
    const recordedCosts: Array<{ target: string; cost: CostTotals }> = [];
    const usage: Usage = {
      inputTokens: 10,
      outputTokens: 20,
      cacheReadTokens: 5,
      cacheWriteTokens: 7,
    };
    const deps: BenchDeps = {
      runFor: async (_observation, meter?: CostMeter) => {
        receivedMeters.push(meter);
        meter?.tick();
        meter?.meter(usage);
        return {
          exploits: [],
          findings: [],
          conversation: { systemPrompt: "sys", messages: [] },
          stopReason: "end_turn" as const,
          cost: { inputTokens: 0, outputTokens: 0, turns: 0 },
        };
      },
      graderFor: () => fakeGrader(),
      onEntryCost: (target, cost) => recordedCosts.push({ target, cost }),
      sink: { save: async () => {} },
    };

    await benchPerturb(
      [resolve(import.meta.dirname, "../../dataset/capability_leak")],
      { ...config, k: 2 },
      deps,
      { twinsPerEntry: 1, twinDumpDir: dump },
    );

    expect(receivedMeters).toHaveLength(4);
    expect(receivedMeters.every((meter) => meter !== undefined)).toBe(true);
    expect(recordedCosts).toEqual([
      { target: "capability_leak", cost: { inputTokens: 72, outputTokens: 80, turns: 4 } },
    ]);
  });

  it("records partial accumulated cost when a later policy run fails", async () => {
    mkdirSync(SCRATCH_ROOT, { recursive: true });
    dump = mkdtempSync(join(SCRATCH_ROOT, "twins-"));
    const recordedCosts: Array<{ target: string; cost: CostTotals }> = [];
    const usage: Usage = {
      inputTokens: 10,
      outputTokens: 20,
      cacheReadTokens: 5,
      cacheWriteTokens: 7,
    };
    let runs = 0;
    const deps: BenchDeps = {
      runFor: async (_observation, meter?: CostMeter) => {
        runs++;
        meter?.tick();
        meter?.meter(usage);
        if (runs === 2) throw new Error("later policy run failed");
        return {
          exploits: [],
          findings: [],
          conversation: { systemPrompt: "sys", messages: [] },
          stopReason: "end_turn" as const,
          cost: { inputTokens: 0, outputTokens: 0, turns: 0 },
        };
      },
      graderFor: () => fakeGrader(),
      onEntryCost: (target, cost) => recordedCosts.push({ target, cost }),
      sink: { save: async () => {} },
    };

    await expect(
      benchPerturb(
        [resolve(import.meta.dirname, "../../dataset/capability_leak")],
        { ...config, k: 2 },
        deps,
        { twinsPerEntry: 1, twinDumpDir: dump },
      ),
    ).rejects.toThrow("later policy run failed");

    expect(recordedCosts).toEqual([
      { target: "capability_leak", cost: { inputTokens: 36, outputTokens: 40, turns: 2 } },
    ]);
  });

  it("isolates an expected agent failure as an incomplete perturbation result", async () => {
    mkdirSync(SCRATCH_ROOT, { recursive: true });
    dump = mkdtempSync(join(SCRATCH_ROOT, "twins-"));
    const recordedCosts: Array<{ target: string; cost: CostTotals }> = [];
    const usage: Usage = {
      inputTokens: 10,
      outputTokens: 20,
      cacheReadTokens: 5,
      cacheWriteTokens: 7,
    };
    const report = await benchPerturb(
      [resolve(import.meta.dirname, "../../dataset/capability_leak")],
      config,
      {
        runFor: async (_observation, meter?: CostMeter) => {
          meter?.tick();
          meter?.meter(usage);
          throw new AgentError("simulated truncation");
        },
        graderFor: () => fakeGrader(),
        onEntryCost: (target, cost) => recordedCosts.push({ target, cost }),
        sink: { save: async () => {} },
      },
      { twinsPerEntry: 1, twinDumpDir: dump },
    );

    expect(report).toEqual({
      complete: false,
      scored: 0,
      errored: 1,
      erroredEntries: [
        {
          target: "capability_leak",
          error: "AgentError: simulated truncation",
          attempts: 1,
        },
      ],
      perEntry: [],
      macro_gap: null,
    });
    expect(recordedCosts).toEqual([
      { target: "capability_leak", cost: { inputTokens: 18, outputTokens: 20, turns: 1 } },
    ]);
  });

  it("filters detect-tier entries before running the model", async () => {
    mkdirSync(SCRATCH_ROOT, { recursive: true });
    dump = mkdtempSync(join(SCRATCH_ROOT, "twins-"));
    const noopSink: TrajectorySink = { save: async () => {} };
    let modelRuns = 0;
    const deps: BenchDeps = {
      runFor: async () => {
        modelRuns++;
        const exploit = {
          finding: { id: "admincap-leak", module: "vault", severity: "critical", title: "t", description: "d" },
          script: { path: "x.mts", contents: "attack" },
        } satisfies Exploit;
        return {
          exploits: [exploit],
          findings: [exploit.finding],
          conversation: { systemPrompt: "sys", messages: [] },
          stopReason: "end_turn" as const,
          cost: { inputTokens: 0, outputTokens: 0, turns: 0 },
        };
      },
      graderFor: () => fakeGrader(),
      sink: noopSink,
    };
    const report = await benchPerturb(
      [
        resolve(import.meta.dirname, "../../dataset/capability_leak"),
        resolve(import.meta.dirname, "../../dataset/staking_time_accounting"),
      ],
      config,
      deps,
      { twinsPerEntry: 2, twinDumpDir: dump },
    );

    expect(report.perEntry.map((entry) => entry.target)).toEqual(["capability_leak"]);
    expect(modelRuns).toBe(3);
  });

  it("rejects when every perturbation target is ineligible before calling the model", async () => {
    let modelRuns = 0;
    await expect(
      benchPerturb(
        [resolve(import.meta.dirname, "../../dataset/staking_time_accounting")],
        config,
        {
          runFor: async () => {
            modelRuns++;
            throw new Error("model must not be called");
          },
          sink: { save: async () => {} },
        },
        { twinsPerEntry: 2, twinDumpDir: join(SCRATCH_ROOT, "unused") },
      ),
    ).rejects.toThrow("no perturbable entries");
    expect(modelRuns).toBe(0);
  });
});
