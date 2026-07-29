import { describe, it, expect } from "vitest";
import { renameHarness, stripTsComments } from "./harness.js";
import type { RenameManifest } from "./types.js";

const manifest: RenameManifest = {
  seed: "t:0",
  packages: ["challenge"],
  moduleRenames: { token: "ivory_5063" },
  all: [
    { kind: "module", from: "token", to: "ivory_5063" },
    { kind: "function", from: "mint", to: "sigma_4930" },
    { kind: "witness", from: "TOKEN", to: "IVORY_5063" },
    { kind: "type", from: "TreasuryCapHolder", to: "Indigo1982" },
  ],
};

describe("renameHarness", () => {
  it("rewrites a qualified moveCall target (module + function)", () => {
    const src = "target: `${ctx.packageId}::token::mint`,";
    expect(renameHarness(src, manifest)).toContain("::ivory_5063::sigma_4930`");
  });

  it("rewrites a qualified type string (module + type)", () => {
    const src = "const T = `${ctx.packageId}::token::TreasuryCapHolder`;";
    expect(renameHarness(src, manifest)).toContain("::ivory_5063::Indigo1982`");
  });

  it("rewrites the OTW witness type string", () => {
    const src = "const TOKEN = `${ctx.packageId}::token::TOKEN`;";
    // the TS local `TOKEN` is untouched; only the ::path:: segments change
    const out = renameHarness(src, manifest);
    expect(out).toContain("const TOKEN =");
    expect(out).toContain("::ivory_5063::IVORY_5063`");
  });

  it("leaves a foreign module path alone (no collision)", () => {
    const src = "const c = `${p}::sui::coin::mint`;"; // not our module
    // `sui` is not in moduleRenames → whole path frozen, incl. the `mint` tail
    expect(renameHarness(src, manifest)).toContain("::sui::coin::mint`");
  });

  it("does not touch a bare TS identifier that merely shares a name", () => {
    const src = "const mint = 3; foo.token = 1;"; // no `::` qualification
    expect(renameHarness(src, manifest)).toEqual(src);
  });

  it("only renames the module segment for a bare-module path", () => {
    const src = "scan(`${p}::token`)"; // module with no trailing symbol
    expect(renameHarness(src, manifest)).toContain("::ivory_5063`");
  });
});

describe("stripTsComments", () => {
  it("removes line comments", () => {
    const out = stripTsComments("const a = 1; // secret\nconst b = 2;");
    expect(out).not.toContain("secret");
    expect(out).toContain("const a = 1;");
    expect(out).toContain("const b = 2;");
  });

  it("removes block comments", () => {
    const out = stripTsComments("/* header\n * BUG: leaks\n */\nconst a = 1;");
    expect(out).not.toContain("BUG");
    expect(out).toContain("const a = 1;");
  });

  it("does NOT strip // inside string / template literals", () => {
    const url = 'const u = "https://example.com/x";';
    expect(stripTsComments(url)).toContain("https://example.com/x");
    const tpl = "const t = `${p}::a::b`; // drop me";
    const out = stripTsComments(tpl);
    expect(out).toContain("`${p}::a::b`");
    expect(out).not.toContain("drop me");
  });

  it("honors escaped quotes in strings", () => {
    const s = 'const s = "a\\"// not a comment";';
    expect(stripTsComments(s)).toContain("// not a comment");
  });

  it("is idempotent", () => {
    const src = "const a = 1; // x\n/* y */ const b = 2;";
    const once = stripTsComments(src);
    expect(stripTsComments(once)).toEqual(once);
  });
});
