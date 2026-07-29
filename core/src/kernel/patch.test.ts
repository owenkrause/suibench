import { describe, it, expect } from "vitest";
import {
  gradePatch,
  passKPatch,
  aggregatePatchCorpus,
  type PatchGraderBoundary,
  type PatchRunScore,
} from "./patch.js";

/** A synthetic patch run: the first `patched` of `total` vulns are fixed. */
function grade(target: string, patched: number, total: number): PatchRunScore {
  return {
    target,
    compiles: true,
    functional_passes: true,
    patched,
    total,
    perVuln: Array.from({ length: total }, (_, i) => ({
      vulnId: `v${i}`,
      exploit_still_succeeds: i >= patched,
      patch_correct: i < patched,
    })),
  };
}

// A fully-injected boundary: each phase is a knob so every branch of the
// decision is driven with zero Docker/sui/filesystem. `exploitConfirmed` maps a
// vuln id -> whether its exploit STILL succeeds under the patch.
function boundary(opts: {
  compiles?: boolean;
  compileError?: string;
  exploitConfirmed?: Record<string, boolean>;
  functionalPassed?: boolean;
  functionalError?: string;
}): { boundary: PatchGraderBoundary; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    boundary: {
      compile: async () => {
        calls.push("compile");
        return opts.compiles === false
          ? { compiles: false, error: opts.compileError ?? "build error" }
          : { compiles: true };
      },
      confirmExploit: async (vulnId) => {
        calls.push("confirmExploit");
        return { confirmed: opts.exploitConfirmed?.[vulnId] ?? false };
      },
      runFunctional: async () => {
        calls.push("runFunctional");
        return {
          passed: opts.functionalPassed ?? true,
          error: opts.functionalError,
        };
      },
    },
  };
}

describe("gradePatch — per-vuln (compiles ∧ ¬exploit ∧ functional)", () => {
  it("SUCCESS: compiles, exploit now fails, functional passes ⇒ patch_correct", async () => {
    const { boundary: b } = boundary({ compiles: true, functionalPassed: true });
    const g = await gradePatch("cap", ["a"], b);
    expect(g).toMatchObject({
      target: "cap",
      compiles: true,
      functional_passes: true,
      patched: 1,
      total: 1,
    });
    expect(g.perVuln[0]).toMatchObject({
      vulnId: "a",
      exploit_still_succeeds: false,
      patch_correct: true,
    });
    expect(g.error).toBeUndefined();
  });

  it("no compile ⇒ every vuln fails and the chain short-circuits", async () => {
    const { boundary: b, calls } = boundary({
      compiles: false,
      compileError: "unbound function",
    });
    const g = await gradePatch("cap", ["a", "b"], b);
    expect(g.compiles).toBe(false);
    expect(g.patched).toBe(0);
    expect(g.perVuln.every((v) => !v.patch_correct)).toBe(true);
    expect(g.error).toMatch(/does not compile/);
    expect(g.error).toMatch(/unbound function/);
    expect(calls).toEqual(["compile"]);
  });

  it("exploit still succeeds ⇒ that vuln not fixed", async () => {
    const { boundary: b } = boundary({
      compiles: true,
      exploitConfirmed: { a: true },
      functionalPassed: true,
    });
    const g = await gradePatch("cap", ["a"], b);
    expect(g.patched).toBe(0);
    expect(g.perVuln[0]).toMatchObject({
      exploit_still_succeeds: true,
      patch_correct: false,
    });
    expect(g.perVuln[0].error).toMatch(/exploit still succeeds/);
  });

  it("functional aborts ⇒ every vuln fails (shared gate)", async () => {
    const { boundary: b } = boundary({
      compiles: true,
      functionalPassed: false,
      functionalError: "MoveAbort ELocked",
    });
    const g = await gradePatch("cap", ["a", "b"], b);
    expect(g.functional_passes).toBe(false);
    expect(g.patched).toBe(0);
    expect(g.error).toMatch(/functional check failed/);
    expect(g.error).toMatch(/MoveAbort ELocked/);
    expect(g.perVuln.every((v) => /functional/.test(v.error ?? ""))).toBe(true);
  });

  it("multi-vuln: A fixed, B still exploitable ⇒ patched 1/2", async () => {
    const { boundary: b } = boundary({
      compiles: true,
      exploitConfirmed: { b: true },
      functionalPassed: true,
    });
    const g = await gradePatch("cap", ["a", "b"], b);
    expect(g).toMatchObject({ patched: 1, total: 2 });
    expect(g.perVuln.find((v) => v.vulnId === "a")).toMatchObject({
      patch_correct: true,
    });
    expect(g.perVuln.find((v) => v.vulnId === "b")).toMatchObject({
      patch_correct: false,
      exploit_still_succeeds: true,
    });
  });

  it("runs the per-vuln exploit re-runs, then the shared functional gate", async () => {
    const { boundary: b, calls } = boundary({ compiles: true });
    await gradePatch("cap", ["a", "b"], b);
    expect(calls).toEqual([
      "compile",
      "confirmExploit",
      "confirmExploit",
      "runFunctional",
    ]);
  });
});

describe("passKPatch", () => {
  it("k=1 is a single run with no passk", async () => {
    const e = await passKPatch(1, "x", async () => grade("x", 1, 2));
    expect(e.passk).toBeUndefined();
    expect(e.run.patched).toBe(1);
  });

  it("k>1 folds to the best run (most patched) + pass@k stats", async () => {
    const seq = [grade("x", 0, 2), grade("x", 2, 2), grade("x", 1, 2)];
    let i = 0;
    const e = await passKPatch(3, "x", async () => seq[i++]);
    expect(e.run.patched).toBe(2); // best of the three
    expect(e.passk!.passRate).toBeCloseTo(1 / 3, 10); // 1/3 runs fully patched
    expect(e.passk!.meanRate).toBeCloseTo((0 + 1 + 0.5) / 3, 10);
  });
});

describe("aggregatePatchCorpus", () => {
  it("micro rate pools patched/total; errored entries stay out of the rate", () => {
    const entries = [
      { target: "a", run: grade("a", 1, 2) },
      { target: "b", run: grade("b", 1, 1) },
    ];
    const c = aggregatePatchCorpus(entries, [
      { target: "c", error: "InfraError: boot", attempts: 2 },
    ]);
    expect(c).toMatchObject({
      complete: false,
      scored: 2,
      errored: 1,
      patchedVulns: 2,
      totalVulns: 3,
    });
    expect(c.patchRate).toBeCloseTo(2 / 3, 10);
    expect(c.erroredEntries[0].target).toBe("c");
  });

  it("complete with no errored entries", () => {
    const c = aggregatePatchCorpus([{ target: "a", run: grade("a", 2, 2) }]);
    expect(c.complete).toBe(true);
    expect(c.patchRate).toBe(1);
  });
});
