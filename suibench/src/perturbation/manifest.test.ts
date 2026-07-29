import { describe, it, expect } from "vitest";
import {
  buildRenameManifest,
  makePrng,
  assertManifestSound,
  RESERVED_FUNCTIONS,
} from "./manifest.js";
import type { EntrySymbols } from "./types.js";

const otwSymbols: EntrySymbols = {
  packages: ["challenge"],
  modules: ["token"],
  types: ["TOKEN", "TreasuryCapHolder"],
  functions: ["init", "mint", "burn", "total_supply"],
  fields: ["id", "cap"],
  constants: [],
  witnesses: ["TOKEN"],
};

describe("makePrng", () => {
  it("is deterministic for a given seed", () => {
    const a = makePrng("seed-x");
    const b = makePrng("seed-x");
    const seqA = Array.from({ length: 8 }, () => a());
    const seqB = Array.from({ length: 8 }, () => b());
    expect(seqA).toEqual(seqB);
  });

  it("differs across seeds", () => {
    const a = Array.from({ length: 8 }, makePrng("seed-a"));
    const b = Array.from({ length: 8 }, makePrng("seed-b"));
    expect(a).not.toEqual(b);
  });

  it("produces values in [0,1)", () => {
    const r = makePrng("range");
    for (let i = 0; i < 1000; i++) {
      const v = r();
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });
});

describe("buildRenameManifest", () => {
  it("is deterministic: same (symbols, seed) => byte-identical manifest", () => {
    const m1 = buildRenameManifest(otwSymbols, "hash:0");
    const m2 = buildRenameManifest(otwSymbols, "hash:0");
    expect(JSON.stringify(m1)).toEqual(JSON.stringify(m2));
  });

  it("different seeds (source_hash + index) => different renamings", () => {
    const m0 = buildRenameManifest(otwSymbols, "hash:0");
    const m1 = buildRenameManifest(otwSymbols, "hash:1");
    expect(m0.moduleRenames.token).not.toEqual(m1.moduleRenames.token);
  });

  it("renames every non-reserved declared module/type/function (closure)", () => {
    const m = buildRenameManifest(otwSymbols, "hash:0");
    const renamed = new Set(m.all.map((r) => r.from));
    // modules, types renamed; functions minus reserved.
    expect(renamed.has("token")).toBe(true);
    expect(renamed.has("TOKEN")).toBe(true);
    expect(renamed.has("TreasuryCapHolder")).toBe(true);
    expect(renamed.has("mint")).toBe(true);
    expect(renamed.has("burn")).toBe(true);
  });

  it("never renames struct fields (frozen — a field spelling routinely aliases a local)", () => {
    const m = buildRenameManifest(otwSymbols, "hash:0");
    expect(m.all.find((r) => r.kind === "field")).toBeUndefined();
    expect(m.all.find((r) => r.from === "cap")).toBeUndefined();
  });

  it("never renames a reserved function (init) or reserved field (id)", () => {
    const m = buildRenameManifest(otwSymbols, "hash:0");
    expect(m.all.find((r) => r.from === "init")).toBeUndefined();
    expect(m.all.find((r) => r.from === "id")).toBeUndefined(); // id: UID is Sui-required
    expect(RESERVED_FUNCTIONS.has("init")).toBe(true);
  });

  it("honors the OTW invariant: witness == new module name upper-cased", () => {
    const m = buildRenameManifest(otwSymbols, "hash:0");
    const newModule = m.moduleRenames.token;
    const witness = m.all.find(
      (r) => r.kind === "witness" && r.from === "TOKEN",
    );
    expect(witness).toBeDefined();
    expect(witness!.to).toEqual(newModule.toUpperCase());
  });

  it("produces a sound manifest (unique from/to, no no-ops)", () => {
    const m = buildRenameManifest(otwSymbols, "hash:0");
    expect(() => assertManifestSound(m.all)).not.toThrow();
    const froms = m.all.map((r) => r.from);
    const tos = m.all.map((r) => r.to);
    expect(new Set(froms).size).toEqual(froms.length);
    expect(new Set(tos).size).toEqual(tos.length);
    for (const r of m.all) expect(r.from).not.toEqual(r.to);
  });

  it("assertManifestSound rejects duplicate targets", () => {
    expect(() =>
      assertManifestSound([
        { kind: "function", from: "a", to: "x_1" },
        { kind: "type", from: "B", to: "x_1" },
      ]),
    ).toThrow(/duplicate rename target/);
  });
});
