import { describe, it, expect, vi } from "vitest";
import {
  runCounterfactuals,
  attribute,
  type CounterfactualBoundary,
  type CounterfactualLabel,
} from "./counterfactual.js";
import type { CheckResult } from "./checks.js";

function makeLabel(id: string): CounterfactualLabel {
  return { id };
}

const saw = (...witnesses: string[]): CheckResult => ({ witnesses });
const A = "bad-debt-no-writeoff";
const B = "collateral-release-no-repay";

describe("runCounterfactuals — exploit x {vulnerable, per-label patch}", () => {
  it("nonempty base: runs each label's patch and collects each complete perLabel result", async () => {
    const labels = [makeLabel("a"), makeLabel("b")];
    const runOnVariant = vi.fn(
      async (
        _entryDir: string,
        _exploitPath: string,
        patch: CounterfactualLabel | null,
      ): Promise<CheckResult> => {
        if (patch === null) return saw("a", "b"); // vulnerable build -> both witnessed
        if (patch.id === "a") return saw("b"); // patch_a removes "a"
        if (patch.id === "b") return saw("a", "b"); // patch_b removes nothing
        throw new Error(`unexpected patch ${patch.id}`);
      },
    );
    const boundary: CounterfactualBoundary<CounterfactualLabel> = {
      runOnVariant,
    };

    const result = await runCounterfactuals(
      "/entry",
      "F1",
      "/exploit.mts",
      labels,
      boundary,
    );

    expect(result).toEqual({
      exploitId: "F1",
      base: saw("a", "b"),
      perLabel: { a: saw("b"), b: saw("a", "b") },
    });
    expect(runOnVariant).toHaveBeenCalledTimes(3);
    expect(runOnVariant).toHaveBeenCalledWith("/entry", "/exploit.mts", null);
  });

  it("empty base witness set: skips per-label runs entirely and returns empty perLabel", async () => {
    const labels = [makeLabel("a"), makeLabel("b")];
    const runOnVariant = vi.fn(
      async (
        _entryDir: string,
        _exploitPath: string,
        patch: CounterfactualLabel | null,
      ): Promise<CheckResult> => {
        if (patch === null) return saw(); // exploit does NOT succeed
        throw new Error("per-label run must not happen when base is empty");
      },
    );
    const boundary: CounterfactualBoundary<CounterfactualLabel> = {
      runOnVariant,
    };

    const result = await runCounterfactuals(
      "/entry",
      "F2",
      "/exploit.mts",
      labels,
      boundary,
    );

    expect(result).toEqual({ exploitId: "F2", base: saw(), perLabel: {} });
    expect(runOnVariant).toHaveBeenCalledTimes(1);
    expect(runOnVariant).toHaveBeenCalledWith("/entry", "/exploit.mts", null);
  });

  it("rejects duplicate configured label ids before running the boundary", async () => {
    const labels = [makeLabel("a"), makeLabel("a")];
    const runOnVariant = vi.fn(async (): Promise<CheckResult> => {
      throw new Error("boundary must not run when the label universe is invalid");
    });
    const boundary: CounterfactualBoundary<CounterfactualLabel> = {
      runOnVariant,
    };

    await expect(
      runCounterfactuals("/entry", "F3", "/exploit.mts", labels, boundary),
    ).rejects.toThrow(/duplicate/i);
    expect(runOnVariant).not.toHaveBeenCalled();
  });

  it("rejects an empty configured label id before running the boundary", async () => {
    const labels = [makeLabel("a"), makeLabel("")];
    const runOnVariant = vi.fn(async (): Promise<CheckResult> => {
      throw new Error("boundary must not run when the label universe is invalid");
    });
    const boundary: CounterfactualBoundary<CounterfactualLabel> = {
      runOnVariant,
    };

    await expect(
      runCounterfactuals("/entry", "F4", "/exploit.mts", labels, boundary),
    ).rejects.toThrow(/non-empty/i);
    expect(runOnVariant).not.toHaveBeenCalled();
  });
});

describe("attribute — base-witness/own-patch subtraction (pure)", () => {
  it("Reference A: {A} base, {} A-patch, {A} B-patch -> A", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: saw(A),
        perLabel: { [A]: saw(), [B]: saw(A) },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({ kind: "attributed", labels: [A] });
  });

  it("Reference B: {B} base, {B} A-patch, {} B-patch -> B", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: saw(B),
        perLabel: { [A]: saw(B), [B]: saw() },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({ kind: "attributed", labels: [B] });
  });

  it("Composite switch: {A} base, {B} A-patch, {A} B-patch -> A (B-patch irrelevant, not a base witness)", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: saw(A),
        perLabel: { [A]: saw(B), [B]: saw(A) },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({ kind: "attributed", labels: [A] });
  });

  it("Historical tripwire: {B} base, {} A-patch, {} B-patch -> B only (A never credited; A absent on base)", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: saw(B),
        perLabel: { [A]: saw(), [B]: saw() },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({ kind: "attributed", labels: [B] });
    expect(a.confirmedLabels).toEqual([B]);
  });

  it("Genuine both: {A,B} base, {B} A-patch, {A} B-patch -> A and B", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: saw(A, B),
        perLabel: { [A]: saw(B), [B]: saw(A) },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({
      kind: "attributed",
      labels: [A, B].sort(),
    });
    expect(a.confirmedLabels).toEqual([A, B].sort());
  });

  it("Patch-invariant A: {A} base, {A} A-patch -> unattributed (own patch didn't remove the witness)", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: saw(A),
        perLabel: { [A]: saw(A), [B]: saw(A, B) },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({ kind: "unattributed", labels: [] });
    expect(a.confirmedLabels).toEqual([]);
  });

  it("No witness: {} base -> refuted, no patch results required", () => {
    const a = attribute([{ exploitId: "F1", base: saw(), perLabel: {} }]);
    expect(a.perExploit["F1"]).toEqual({ kind: "refuted", labels: [] });
  });

  it("does not attribute a label merely because its patched result is empty when it wasn't a base witness", () => {
    // B-patch is empty, but B was never in base.witnesses -> B must not appear.
    const a = attribute([
      {
        exploitId: "F1",
        base: saw(A),
        perLabel: { [A]: saw(A), [B]: saw() },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({ kind: "unattributed", labels: [] });
  });

  it("keeps base rejection distinct from accepted-but-unattributed", () => {
    const a = attribute([
      { exploitId: "F3", base: saw(A), perLabel: { [A]: saw(A) } }, // patch-invariant
      { exploitId: "F4", base: saw(), perLabel: {} }, // never worked
    ]);
    expect(a.perExploit["F3"].kind).toBe("unattributed");
    expect(a.perExploit["F4"].kind).toBe("refuted");
  });

  it("union recall dedups overlap across exploits", () => {
    const a = attribute([
      { exploitId: "F1", base: saw(A), perLabel: { [A]: saw(), [B]: saw(A) } },
      { exploitId: "F2", base: saw(A), perLabel: { [A]: saw(), [B]: saw(A) } },
    ]);
    expect(a.confirmedLabels).toEqual([A]);
  });

  it("one script covering {a,b,c} contributes all three to confirmedLabels", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: saw("a", "b", "c"),
        perLabel: { a: saw(), b: saw(), c: saw() },
      },
    ]);
    expect(a.perExploit["F1"]).toEqual({
      kind: "attributed",
      labels: ["a", "b", "c"],
    });
    expect(a.confirmedLabels).toEqual(["a", "b", "c"]);
  });

  it("dedupGroups: scripts with equal attr signatures share a group", () => {
    const a = attribute([
      { exploitId: "F1", base: saw("a"), perLabel: { a: saw() } }, // {a}
      { exploitId: "F2", base: saw("a"), perLabel: { a: saw() } }, // {a}
      { exploitId: "F5", base: saw("b"), perLabel: { b: saw() } }, // {b}
    ]);
    const groupOf = (id: string) => a.dedupGroups.find((g) => g.includes(id));
    expect(groupOf("F1")).toEqual(groupOf("F2"));
    expect(groupOf("F1")!.sort()).toEqual(["F1", "F2"]);
    expect(groupOf("F5")!.sort()).toEqual(["F5"]);
  });

  it("dedupGroups contains confirmed exploits only and preserves unattributed state", () => {
    const a = attribute([
      { exploitId: "accepted-1", base: saw("a"), perLabel: { a: saw() } },
      { exploitId: "accepted-2", base: saw("a"), perLabel: { a: saw() } },
      { exploitId: "rejected", base: saw(), perLabel: {} },
    ]);

    expect(a.dedupGroups).toEqual([["accepted-1", "accepted-2"]]);
    expect(a.dedupGroups.flat()).not.toContain("rejected");
  });

  it("sorts labels and their union deterministically", () => {
    const a = attribute([
      { exploitId: "F1", base: saw("z", "a"), perLabel: { z: saw(), a: saw() } },
      { exploitId: "F2", base: saw("m"), perLabel: { m: saw() } },
    ]);

    expect(a.perExploit["F1"]).toEqual({ kind: "attributed", labels: ["a", "z"] });
    expect(a.confirmedLabels).toEqual(["a", "m", "z"]);
  });

  it("rejects duplicate exploit IDs instead of overwriting", () => {
    expect(() =>
      attribute([
        { exploitId: "duplicate", base: saw(), perLabel: {} },
        { exploitId: "duplicate", base: saw("a"), perLabel: { a: saw() } },
      ]),
    ).toThrow(/duplicate exploit id/i);
  });

  it("errors when a base-witnessed label has no own-patch result", () => {
    expect(() =>
      attribute([{ exploitId: "F1", base: saw(A), perLabel: {} }]),
    ).toThrow(/missing patch result for base witness "bad-debt-no-writeoff"/);
  });

  it("worked example (F1..F4): union recall with all three states", () => {
    const a = attribute([
      { exploitId: "F1", base: saw("a"), perLabel: { a: saw() } }, // {a}
      { exploitId: "F2", base: saw("b"), perLabel: { b: saw() } }, // {b}
      { exploitId: "F3", base: saw("a"), perLabel: { a: saw("a") } }, // {} patch-invariant
      { exploitId: "F4", base: saw(), perLabel: {} }, // never worked
    ]);
    expect(a.confirmedLabels).toEqual(["a", "b"]);
    expect(a.perExploit["F3"].kind).toBe("unattributed");
    expect(a.perExploit["F4"].kind).toBe("refuted");
  });
});
