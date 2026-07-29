import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { benchPerturb } from "./perturb-driver.js";
import type { BenchDeps, RunConfig } from "./driver.js";
import type { Grader, Mount, MoveFile, ChainSnapshot } from "core";

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
const config: RunConfig = { harness: "harnessed", axis: "exploitation", env: { network: "none", model: "none", effort: "low" }, k: 1 };

const PKG = "0xpkg";
const ATTACKER = "0xattacker";
const ADMIN = "0xadmin";

function emptySnapshot(): ChainSnapshot {
  return { balances: { byAddress: {} }, objects: { ownerOf: {}, byId: {} }, events: { events: [] } };
}

function vulnerableSnapshot(capType: string): ChainSnapshot {
  return {
    balances: { byAddress: {} },
    objects: {
      ownerOf: { cap1: ATTACKER, cap0: ADMIN },
      byId: {
        cap1: { owner: ATTACKER, type: capType, fields: {} },
        cap0: { owner: ADMIN, type: capType, fields: {} },
      },
    },
    events: { events: [] },
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
    const deps: BenchDeps = {
      policyFor: () => ({
        act: async () => ({
          kind: "report_exploit",
          exploit: {
            finding: { id: "admincap-leak", module: "vault", severity: "critical", title: "t", description: "d" },
            script: { path: "x.mts", contents: "attack" },
          },
        }),
      }),
      graderFor: () => fakeGrader(),
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
});
