import { describe, it, expect } from "vitest";
import { extractSymbols, stripMoveComments } from "./parser.js";

const SRC = `module challenge::vault {
    public struct Vault has key { id: UID, balance: u64 }
    public struct AdminCap has key, store { id: UID }
    public fun withdraw(_c: &AdminCap, v: &mut Vault, amt: u64) { v.balance = v.balance - amt; }
    fun helper(x: u64): u64 { x + 1 }
}`;

describe("parser", () => {
  it("extracts modules, types, functions, fields from Move source", async () => {
    const syms = await extractSymbols([{ relPath: "sources/vault.move", content: SRC }]);
    expect(syms.modules).toContain("vault");
    expect(syms.types).toEqual(expect.arrayContaining(["Vault", "AdminCap"]));
    expect(syms.functions).toEqual(expect.arrayContaining(["withdraw", "helper"]));
    expect(syms.fields).toEqual(expect.arrayContaining(["balance"]));
  });

  it("strips comments", async () => {
    const out = await stripMoveComments("// a comment\nmodule c::m {}\n");
    expect(out).not.toContain("a comment");
    expect(out).toContain("module c::m");
  });
});
