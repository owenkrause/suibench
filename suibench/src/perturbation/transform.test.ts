import { describe, it, expect } from "vitest";
import { generateTwin, stripEntry } from "./transform.js";
import type { EntryFiles } from "./types.js";

const ENTRY: EntryFiles = {
  entry: {
    id: "chal_00000001",
    version: 1,
    vulns: [{ id: "admincap-leak", module: "vault", title: "AdminCap leaks", severity: "critical", harm: "state", root_cause: "mints a cap to any caller" }],
  },
  files: {
    "Move.toml": `[package]\nname = "challenge"\n[addresses]\nchallenge = "0x0"\n`,
    "sources/vault.move": `module challenge::vault {\n  public struct AdminCap has key, store { id: UID }\n  public fun request_admin_status(ctx: &mut TxContext): AdminCap { AdminCap { id: object::new(ctx) } } // BUG\n}\n`,
    "check.ts": `import { type Check, type CheckResult, ownedObjects } from "core";\nconst LABEL_ID = "admincap-leak" as const;\nexport const check: Check = (delta, params): CheckResult => { const witnessed = ownedObjects(delta.post, params.attackerAddress, \`\${params.packageId}::vault::AdminCap\`).length > 0; return { witnesses: witnessed ? [LABEL_ID] : [] }; };\n`,
    "exploits/admincap-leak.ts": `import { Transaction } from "@mysten/sui/transactions";\nexport async function attack(ctx: any) { const tx = new Transaction(); tx.moveCall({ target: \`\${ctx.packageId}::vault::request_admin_status\` }); }\n`,
    "entry.json": `{"version":1}`,
  },
};

describe("generateTwin", () => {
  it("is deterministic for a fixed seed", async () => {
    const a = await generateTwin(ENTRY, "seed-1");
    const b = await generateTwin(ENTRY, "seed-1");
    expect(a.files).toEqual(b.files);
  });

  it("renames the module consistently across sources, check.ts, exploit, and entry.json", async () => {
    const t = await generateTwin(ENTRY, "seed-1");
    const byPath = Object.fromEntries(t.files.map((f) => [f.relPath, f.content]));
    const newModule = t.manifest.moduleRenames["vault"];
    expect(newModule).toBeDefined();
    expect(newModule).not.toBe("vault");
    // sources renamed
    expect(byPath["sources/vault.move"]).toContain(`::${newModule}`);
    expect(byPath["sources/vault.move"]).not.toMatch(/\bvault\b/);
    // harness (check + exploit) mirror the rename
    expect(byPath["check.ts"]).toContain(`::${newModule}::`);
    expect(byPath["exploits/admincap-leak.ts"]).toContain(`::${newModule}::`);
    // entry.json module field renamed, id/title/root_cause PRESERVED
    const ej = JSON.parse(byPath["entry.json"]);
    expect(ej.vulns[0].module).toBe(newModule);
    expect(ej.vulns[0].id).toBe("admincap-leak");
    expect(ej.vulns[0].title).toBe("AdminCap leaks");
    expect(ej.vulns[0].root_cause).toBe("mints a cap to any caller");
  });

  it("strips comments (so the BUG marker is gone)", async () => {
    const t = await generateTwin(ENTRY, "seed-1");
    const src = t.files.find((f) => f.relPath === "sources/vault.move")!.content;
    expect(src).not.toContain("BUG");
  });
});

describe("stripEntry", () => {
  it("strips comments but preserves module/function names (no rename)", async () => {
    const s = await stripEntry(ENTRY);
    const byPath = Object.fromEntries(s.files.map((f) => [f.relPath, f.content]));
    // comments gone
    expect(byPath["sources/vault.move"]).not.toContain("BUG");
    // no rename: original identifiers preserved
    expect(byPath["sources/vault.move"]).toContain("challenge::vault");
    expect(byPath["sources/vault.move"]).toContain("request_admin_status");
    expect(byPath["check.ts"]).toContain("::vault::AdminCap");
    expect(byPath["exploits/admincap-leak.ts"]).toContain("::vault::request_admin_status");
    // entry.json unchanged
    expect(byPath["entry.json"]).toBe(ENTRY.files["entry.json"]);
  });
});
