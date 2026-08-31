import { describe, it, expect } from "vitest";
import { parseManifest, CHAL_ID_RE } from "./manifest.js";

const base = { id: "chal_7f3k9m2q", vulns: [{ id: "v1", module: "m", title: "t", severity: "high", root_cause: "r", harm: "state" }] };

it("parses a valid top-level chal_ id", () => {
  expect(parseManifest(JSON.stringify(base), "e").id).toBe("chal_7f3k9m2q");
});
it("rejects a missing id", () => {
  const { id, ...noId } = base;
  expect(() => parseManifest(JSON.stringify(noId), "e")).toThrow(/"id"/);
});
it("rejects a malformed id", () => {
  expect(() => parseManifest(JSON.stringify({ ...base, id: "swap_bug" }), "e")).toThrow(/chal_/);
});
it("CHAL_ID_RE matches the format", () => {
  expect(CHAL_ID_RE.test("chal_7f3k9m2q")).toBe(true);
  expect(CHAL_ID_RE.test("chal_ABC")).toBe(false);
});
