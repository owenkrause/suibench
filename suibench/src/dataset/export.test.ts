import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { loadEntry } from "./entry.js";
import { exportEntry, sourceDigest } from "./export.js";

const DATASET = resolve(import.meta.dirname, "../../dataset");

const e = () => loadEntry(resolve(DATASET, "flash_loan_misuse"));

describe("exportEntry / sourceDigest", () => {
  it("exportEntry returns Move.toml + sources, sorted by path", () => {
    const files = exportEntry(e());
    expect(files.some((f) => f.path.endsWith("Move.toml"))).toBe(true);
    expect(files.every((f) => f.path === "Move.toml" || f.path.startsWith("sources/"))).toBe(true);
    expect(files.map((f) => f.path)).toEqual([...files.map((f) => f.path)].sort());
  });

  it("sourceDigest is stable and content-sensitive", () => {
    const d1 = sourceDigest(e());
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
    expect(sourceDigest(e())).toBe(d1);
  });
});
