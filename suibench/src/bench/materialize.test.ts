import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readEntryFiles, writeTwinDir, twinSeed } from "./materialize.js";
import { generateTwin } from "../perturbation/transform.js";
import { loadEntry } from "../dataset/index.js";

function scratchEntry(): string {
  const d = mkdtempSync(join(tmpdir(), "twin-src-"));
  mkdirSync(join(d, "sources"), { recursive: true });
  mkdirSync(join(d, "exploits"), { recursive: true });
  writeFileSync(join(d, "Move.toml"), `[package]\nname="challenge"\n`);
  writeFileSync(join(d, "entry.json"), JSON.stringify({ version: 1, vulns: [{ id: "admincap-leak", module: "vault", title: "t", severity: "critical", root_cause: "r" }] }));
  writeFileSync(join(d, "sources/vault.move"), `module challenge::vault {\n  public fun request_admin_status() {}\n}\n`);
  writeFileSync(join(d, "check.ts"), `import { type Check } from "core";\nexport const check: Check = () => true;\n`);
  writeFileSync(join(d, "exploits/admincap-leak.ts"), `export async function attack() {}\n`);
  return d;
}

describe("materialize", () => {
  it("twinSeed is deterministic", () => {
    expect(twinSeed("vault", 0)).toBe(twinSeed("vault", 0));
    expect(twinSeed("vault", 0)).not.toBe(twinSeed("vault", 1));
  });

  it("round-trips: read entry → generate twin → write dir → loadEntry accepts it", async () => {
    const src = scratchEntry();
    const files = readEntryFiles(src);
    const twin = await generateTwin(files, twinSeed("vault", 0));
    const out = mkdtempSync(join(tmpdir(), "twin-out-"));
    writeTwinDir(out, twin);
    expect(existsSync(join(out, "entry.json"))).toBe(true);
    const e = loadEntry(out);
    expect(e.tier).toBe("confirmed"); // check.ts present
    expect(Object.keys(e.exploits)).toEqual(["admincap-leak"]); // id stable → filename stable
  });
});
