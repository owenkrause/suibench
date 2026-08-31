import { describe, expect, it } from "vitest";
import { MAX_FINDINGS, ValidationError, parseSubmission } from "./validate.js";

const ok = {
  datasetVersion: "v",
  entryId: "chal_7f3k9m2q",
  findings: [
    {
      finding: { id: "a", module: "m", severity: "high", title: "t", description: "d" },
      script: { path: "e.mts", contents: "export async function attack(){}" },
    },
  ],
};

describe("parseSubmission", () => {
  it("accepts a well-formed submission", () => {
    const parsed = parseSubmission(ok);
    expect(parsed.datasetVersion).toBe("v");
    expect(parsed.entryId).toBe("chal_7f3k9m2q");
    expect(parsed.findings.length).toBe(1);
  });

  it("rejects too many findings", () => {
    const many = { ...ok, findings: Array.from({ length: MAX_FINDINGS + 1 }, () => ok.findings[0]) };
    expect(() => parseSubmission(many)).toThrow(ValidationError);
  });

  it("rejects zero findings", () => {
    expect(() => parseSubmission({ ...ok, findings: [] })).toThrow(ValidationError);
  });

  it("rejects a malformed finding/script", () => {
    expect(() => parseSubmission({ ...ok, findings: [{ finding: {}, script: {} }] })).toThrow(ValidationError);
  });

  it("rejects a missing datasetVersion", () => {
    const { datasetVersion, ...rest } = ok;
    expect(() => parseSubmission(rest)).toThrow(ValidationError);
  });

  it("rejects a missing entryId", () => {
    const { entryId, ...rest } = ok;
    expect(() => parseSubmission(rest)).toThrow(ValidationError);
  });

  it("rejects an oversized script", () => {
    const big = {
      ...ok,
      findings: [
        {
          finding: ok.findings[0].finding,
          script: { path: "e.mts", contents: "x".repeat(256 * 1024 + 1) },
        },
      ],
    };
    expect(() => parseSubmission(big)).toThrow(ValidationError);
  });

  it("rejects a non-object body", () => {
    expect(() => parseSubmission("nope")).toThrow(ValidationError);
  });
});
