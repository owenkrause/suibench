import { describe, it, expect } from "vitest";
import { FOUNDATIONAL_CONTEXT } from "./prompt.js";

describe("FOUNDATIONAL_CONTEXT", () => {
  it("exports non-empty shared Sui/Move security knowledge", () => {
    expect(typeof FOUNDATIONAL_CONTEXT).toBe("string");
    expect(FOUNDATIONAL_CONTEXT.length).toBeGreaterThan(0);
    expect(FOUNDATIONAL_CONTEXT).toContain("Sui/Move Security Foundations");
  });
});
