// Unit-tests the PURE per-vuln patch-grading helper `isVulnStillWitnessed`
// WITHOUT Docker/Confirmer. It is the dual of the exploitation boundary: same
// `runCheck` authoring guard, reduced to ONE label's membership. The critical
// invariant is that "any witness remains" must NOT be conflated with
// "THIS vuln remains" — a multi-vuln entry's patch for A must grade solely on
// whether A is still witnessed, independent of whatever else the check reports.
import { describe, it, expect } from "vitest";
import type { Check, ChainSnapshot, GraderResult } from "core";
import { isVulnStillWitnessed } from "./patch-grader.js";

function emptySnapshot(): ChainSnapshot {
  return { balances: { byAddress: {} }, objects: { ownerOf: {}, byId: {} } };
}

function graderResult(): GraderResult {
  return {
    delta: { pre: emptySnapshot(), post: emptySnapshot() },
    params: { packageId: "0xpkg", attackerAddress: "0xattacker" },
    evidence: { attackTransactions: [] },
  };
}

const ALLOWED = ["A", "B"];

describe("isVulnStillWitnessed — label-specific patch grading", () => {
  it("a result witnessing only B: patch-for-A is defeated (false), patch-for-B still succeeds (true)", () => {
    const checkReturnsB: Check = () => ({ witnesses: ["B"] });
    expect(isVulnStillWitnessed("A", ALLOWED, checkReturnsB, graderResult())).toBe(false);
    expect(isVulnStillWitnessed("B", ALLOWED, checkReturnsB, graderResult())).toBe(true);
  });

  it("does not treat 'any witness remains' as 'A remains' — {A,B} witnessed, patch grades true for BOTH independently", () => {
    const checkReturnsBoth: Check = () => ({ witnesses: ["A", "B"] });
    expect(isVulnStillWitnessed("A", ALLOWED, checkReturnsBoth, graderResult())).toBe(true);
    expect(isVulnStillWitnessed("B", ALLOWED, checkReturnsBoth, graderResult())).toBe(true);
  });

  it("empty witness set: every vuln's patch is graded defeated", () => {
    const checkReturnsNone: Check = () => ({ witnesses: [] });
    expect(isVulnStillWitnessed("A", ALLOWED, checkReturnsNone, graderResult())).toBe(false);
    expect(isVulnStillWitnessed("B", ALLOWED, checkReturnsNone, graderResult())).toBe(false);
  });

  it("invokes the check exactly once per call", () => {
    let calls = 0;
    const countingCheck: Check = () => {
      calls++;
      return { witnesses: ["A"] };
    };
    isVulnStillWitnessed("A", ALLOWED, countingCheck, graderResult());
    expect(calls).toBe(1);
  });

  it("rejects a boolean check result cast through unknown (malformed shape)", () => {
    const booleanCheck = (() => true) as unknown as Check;
    expect(() => isVulnStillWitnessed("A", ALLOWED, booleanCheck, graderResult())).toThrow(
      /must be an object/,
    );
  });

  it("rejects a requested vulnId that is not in the manifest's allowed set — a grading error, not an implicit defeat", () => {
    const check: Check = () => ({ witnesses: [] });
    expect(() => isVulnStillWitnessed("typo-id", ALLOWED, check, graderResult())).toThrow(
      /not in the manifest witness set/,
    );
  });

  it("rejects a check result witnessing an id outside the allowed manifest set", () => {
    const checkReturnsUnknown: Check = () => ({ witnesses: ["not-in-manifest"] });
    expect(() => isVulnStillWitnessed("A", ALLOWED, checkReturnsUnknown, graderResult())).toThrow(
      /unknown id/,
    );
  });
});
