import { describe, it, expect } from "vitest";
import { referenceLibrary, REFERENCE_CATALOG } from "./references.js";

describe("referenceLibrary", () => {
  it("list() names every catalog entry", () => {
    const list = referenceLibrary.list();
    for (const e of REFERENCE_CATALOG) expect(list).toContain(e.name);
  });

  it("read() loads a known reference off disk", () => {
    const sp = referenceLibrary.read("sui-patterns");
    expect(sp.startsWith("Error")).toBe(false);
    expect(sp.length).toBeGreaterThan(1000);
  });

  it("read() reports an unknown reference by name", () => {
    expect(referenceLibrary.read("nope")).toContain('unknown reference "nope"');
  });
});
