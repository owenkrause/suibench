import { describe, it, expect, vi } from "vitest";
import {
  runCounterfactuals,
  attribute,
  type CounterfactualBoundary,
  type CounterfactualLabel,
} from "./counterfactual.js";

function makeLabel(id: string): CounterfactualLabel {
  return { id };
}

describe("runCounterfactuals — exploit x {vulnerable, per-label patch}", () => {
  it("base=true: runs each label's patch and collects perLabel results", async () => {
    const labels = [makeLabel("a"), makeLabel("b")];
    const runOnVariant = vi.fn(
      async (
        _entryDir: string,
        _exploitPath: string,
        patch: CounterfactualLabel | null,
      ) => {
        if (patch === null) return true; // vulnerable build -> exploit succeeds
        if (patch.id === "a") return false; // patch_a breaks it
        if (patch.id === "b") return true; // patch_b doesn't
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
      base: true,
      perLabel: { a: false, b: true },
    });
    expect(runOnVariant).toHaveBeenCalledTimes(3);
    expect(runOnVariant).toHaveBeenCalledWith("/entry", "/exploit.mts", null);
  });

  it("base=false: skips per-label runs entirely", async () => {
    const labels = [makeLabel("a"), makeLabel("b")];
    const runOnVariant = vi.fn(
      async (
        _entryDir: string,
        _exploitPath: string,
        patch: CounterfactualLabel | null,
      ) => {
        if (patch === null) return false; // exploit does NOT succeed
        throw new Error("per-label run must not happen when base=false");
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

    expect(result).toEqual({ exploitId: "F2", base: false, perLabel: {} });
    expect(runOnVariant).toHaveBeenCalledTimes(1);
    expect(runOnVariant).toHaveBeenCalledWith("/entry", "/exploit.mts", null);
  });
});

describe("attribute — attribution core (pure)", () => {
  it("attr(exploit) = { L : base ∧ ¬perLabel[L] }", () => {
    const a = attribute([
      { exploitId: "F1", base: true, perLabel: { a: false, b: true } }, // -> {a}
    ]);
    expect(a.perExploit["F1"].sort()).toEqual(["a"]);
  });

  it("union recall dedups overlap", () => {
    const a = attribute([
      { exploitId: "F1", base: true, perLabel: { a: false, b: true } },
      { exploitId: "F2", base: true, perLabel: { a: false, b: true } },
    ]);
    expect(a.confirmedLabels.sort()).toEqual(["a"]);
  });

  it("one script covering {a,b,c} contributes all three to confirmedLabels", () => {
    const a = attribute([
      {
        exploitId: "F1",
        base: true,
        perLabel: { a: false, b: false, c: false },
      },
    ]);
    expect(a.perExploit["F1"].sort()).toEqual(["a", "b", "c"]);
    expect(a.confirmedLabels.sort()).toEqual(["a", "b", "c"]);
  });

  it("base=true but patch-invariant -> EMPTY perExploit (a false positive, no split)", () => {
    const a = attribute([
      { exploitId: "F3", base: true, perLabel: { a: true, b: true } },
    ]);
    expect(a.perExploit["F3"]).toEqual([]);
    expect(a.confirmedLabels).toEqual([]);
  });

  it("base=false -> EMPTY perExploit (also a false positive, same bucket)", () => {
    const a = attribute([{ exploitId: "F4", base: false, perLabel: {} }]);
    expect(a.perExploit["F4"]).toEqual([]);
  });

  it("base=false AND base=true-patch-invariant both land in the empty-perExploit bucket", () => {
    const a = attribute([
      { exploitId: "F3", base: true, perLabel: { a: true, b: true } }, // patch-invariant
      { exploitId: "F4", base: false, perLabel: {} }, // never worked
    ]);
    expect(a.perExploit["F3"]).toEqual([]);
    expect(a.perExploit["F4"]).toEqual([]);
    const empty = Object.entries(a.perExploit)
      .filter(([, h]) => h.length === 0)
      .map(([id]) => id)
      .sort();
    expect(empty).toEqual(["F3", "F4"]);
  });

  it("dedupGroups: scripts with equal attr signatures share a group", () => {
    const a = attribute([
      { exploitId: "F1", base: true, perLabel: { a: false, b: true } }, // {a}
      { exploitId: "F2", base: true, perLabel: { a: false, b: true } }, // {a}
      { exploitId: "F5", base: true, perLabel: { a: true, b: false } }, // {b}
    ]);
    const groupOf = (id: string) => a.dedupGroups.find((g) => g.includes(id));
    expect(groupOf("F1")).toEqual(groupOf("F2"));
    expect(groupOf("F1")!.sort()).toEqual(["F1", "F2"]);
    expect(groupOf("F5")!.sort()).toEqual(["F5"]);
  });

  it("worked example (F1..F4): union recall; F3+F4 both empty (false positives)", () => {
    const a = attribute([
      { exploitId: "F1", base: true, perLabel: { a: false, b: true } }, // {a}
      { exploitId: "F2", base: true, perLabel: { a: true, b: false } }, // {b}
      { exploitId: "F3", base: true, perLabel: { a: true, b: true } }, // {} patch-invariant
      { exploitId: "F4", base: false, perLabel: {} }, // never worked
    ]);
    expect(a.confirmedLabels.sort()).toEqual(["a", "b"]);
    expect(a.perExploit["F3"]).toEqual([]);
    expect(a.perExploit["F4"]).toEqual([]);
  });
});
