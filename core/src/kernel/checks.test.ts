import { describe, it, expect } from "vitest";
import type { ChainSnapshot, ChainDelta, ObjectState } from "./types.js";
import { ownerAddress } from "./types.js";
import {
  balanceAt,
  balanceGained,
  ownedObjects,
  ownedObjectFields,
  sharedObjects,
  sharedObjectFields,
  clockTimestampMs,
  fieldAsBigInt,
  validateCheckResult,
  runCheck,
  successfulMoveEvents,
  type Check,
  type CheckEvidence,
  type CheckParams,
  type AttackTransactionEvidence,
} from "./checks.js";

const PKG = "0x0abc";

/** Build a snapshot from per-address per-coin balances and (optionally) objects. */
function snap(
  balances: Record<string, Record<string, bigint>>,
  objects: Record<string, ObjectState> = {},
): ChainSnapshot {
  const ownerOf: Record<string, string | null> = {};
  for (const [id, o] of Object.entries(objects)) ownerOf[id] = ownerAddress(o.owner);
  return {
    balances: { byAddress: balances },
    objects: { ownerOf, byId: objects },
  };
}

describe("balanceAt — canonical-form coin-type matching", () => {
  it("reads an exact key", () => {
    const s = snap({ "0xatk": { [`${PKG}::token::TOKEN`]: 1000n } });
    expect(balanceAt(s, "0xatk", `${PKG}::token::TOKEN`)).toBe(1000n);
  });

  it("matches a short-form stored key against a padded query", () => {
    // stored under the leading-zero-stripped address (the getAllBalances quirk)
    const s = snap({ "0xatk": { "0xabc::token::TOKEN": 1000n } });
    // query built from the 64-char packageId still resolves
    const padded = "0x" + "abc".padStart(64, "0") + "::token::TOKEN";
    expect(balanceAt(s, "0xatk", padded)).toBe(1000n);
  });

  it("missing address / coin reads 0", () => {
    expect(balanceAt(snap({}), "0xatk", "0x2::sui::SUI")).toBe(0n);
  });
});

describe("balanceGained — post minus pre", () => {
  it("is the delta and can be negative", () => {
    const delta: ChainDelta = {
      pre: snap({ "0xatk": { T: 100n } }),
      post: snap({ "0xatk": { T: 400n } }),
    };
    expect(balanceGained(delta, "0xatk", "T")).toBe(300n);
    expect(balanceGained(delta, "0xother", "T")).toBe(0n);
  });
});

describe("ownedObjects / ownedObjectFields — parsed reads from the snapshot (no client)", () => {
  const share = (owner: string, shares: string): ObjectState => ({
    owner: { AddressOwner: owner },
    type: `${PKG}::reward_pool::ShareToken`,
    fields: { shares },
  });

  it("ownedObjects returns every matching object owned by the address", () => {
    const s = snap({}, { a: share("0xuser", "0"), b: share("0xuser", "5") });
    const found = ownedObjects(s, "0xuser", `${PKG}::reward_pool::ShareToken`);
    expect(found.map((o) => o.fields.shares).sort()).toEqual(["0", "5"]);
  });

  it("ownedObjects respects owner and type (padded match)", () => {
    const s = snap({}, { a: share("0xuser", "1"), b: share("0xother", "9") });
    const padded = "0x" + "abc".padStart(64, "0") + "::reward_pool::ShareToken";
    expect(ownedObjects(s, "0xuser", padded)).toHaveLength(1);
    expect(ownedObjects(s, "0xnobody", padded)).toHaveLength(0);
  });

  it("ownedObjectFields returns the first match's fields, or null", () => {
    const s = snap({}, { a: share("0xuser", "0") });
    expect(
      ownedObjectFields(s, "0xuser", `${PKG}::reward_pool::ShareToken`),
    ).toEqual({ shares: "0" });
    expect(ownedObjectFields(snap({}), "0xuser", "T")).toBeNull();
  });
});

describe("sharedObjects / sharedObjectFields / clockTimestampMs — shared + clock reads", () => {
  const pool = (liquidity: string): ObjectState => ({
    owner: { Shared: { initial_shared_version: "3" } },
    type: `${PKG}::pool::Pool`,
    fields: { liquidity },
  });
  const clock = (ms: string): ObjectState => ({
    owner: { Shared: { initial_shared_version: "1" } },
    type: "0x2::clock::Clock",
    fields: { timestamp_ms: ms },
  });

  it("sharedObjects returns shared objects of the type; ignores an owned one", () => {
    const s = snap({}, {
      p: pool("100"),
      owned: { owner: { AddressOwner: "0xu" }, type: `${PKG}::pool::Pool`, fields: { liquidity: "9" } },
    });
    expect(sharedObjects(s, `${PKG}::pool::Pool`).map((o) => o.fields.liquidity)).toEqual(["100"]);
  });

  it("sharedObjectFields returns the first shared match's fields, or null", () => {
    expect(sharedObjectFields(snap({}, { p: pool("100") }), `${PKG}::pool::Pool`)?.liquidity).toBe("100");
    expect(sharedObjectFields(snap({}), `${PKG}::pool::Pool`)).toBeNull();
  });

  it("clockTimestampMs reads the Clock by type under its padded id, or null", () => {
    const padded = "0x" + "6".padStart(64, "0");
    expect(clockTimestampMs(snap({}, { [padded]: clock("1786") }))).toBe(1786n);
    expect(clockTimestampMs(snap({}))).toBeNull();
  });
});

describe("fieldAsBigInt — numeric Move field as bigint", () => {
  it("reads string / number / bigint; null on absent or non-numeric", () => {
    expect(fieldAsBigInt({ shares: "0" }, "shares")).toBe(0n);
    expect(fieldAsBigInt({ shares: 42 }, "shares")).toBe(42n);
    expect(fieldAsBigInt({ shares: 7n }, "shares")).toBe(7n);
    expect(fieldAsBigInt({}, "shares")).toBeNull();
    expect(fieldAsBigInt({ shares: { nested: true } }, "shares")).toBeNull();
  });
});

describe("validateCheckResult — trusted-checker authoring guard", () => {
  const LABELS = ["a", "b", "c"];

  it("accepts an empty witness set", () => {
    expect(validateCheckResult({ witnesses: [] }, LABELS)).toEqual({ witnesses: [] });
  });

  it("accepts a singleton witness set", () => {
    expect(validateCheckResult({ witnesses: ["a"] }, LABELS)).toEqual({ witnesses: ["a"] });
  });

  it("accepts a multi-witness set", () => {
    expect(validateCheckResult({ witnesses: ["a", "b"] }, LABELS)).toEqual({
      witnesses: ["a", "b"],
    });
  });

  it("sorts witnesses deterministically", () => {
    expect(validateCheckResult({ witnesses: ["b", "a"] }, LABELS)).toEqual({
      witnesses: ["a", "b"],
    });
  });

  it("rejects non-object values", () => {
    expect(() => validateCheckResult(true, LABELS)).toThrow();
    expect(() => validateCheckResult(null, LABELS)).toThrow();
    expect(() => validateCheckResult(undefined, LABELS)).toThrow();
    expect(() => validateCheckResult("a", LABELS)).toThrow();
    expect(() => validateCheckResult(1, LABELS)).toThrow();
  });

  it("rejects a missing witnesses field", () => {
    expect(() => validateCheckResult({}, LABELS)).toThrow();
  });

  it("rejects a non-array witnesses field", () => {
    expect(() => validateCheckResult({ witnesses: "a" }, LABELS)).toThrow();
    expect(() => validateCheckResult({ witnesses: { a: true } }, LABELS)).toThrow();
  });

  it("rejects non-string or empty-string witness ids", () => {
    expect(() => validateCheckResult({ witnesses: [1] }, LABELS)).toThrow();
    expect(() => validateCheckResult({ witnesses: [""] }, LABELS)).toThrow();
    expect(() => validateCheckResult({ witnesses: [null] }, LABELS)).toThrow();
  });

  it("rejects duplicate witness ids rather than deduping them", () => {
    expect(() => validateCheckResult({ witnesses: ["a", "a"] }, LABELS)).toThrow();
  });

  it("rejects witness ids absent from the supplied manifest list", () => {
    expect(() => validateCheckResult({ witnesses: ["z"] }, LABELS)).toThrow();
  });

  it("does not mutate the check-owned input array", () => {
    const witnesses = ["b", "a"];
    const input = { witnesses };
    const result = validateCheckResult(input, LABELS);
    expect(witnesses).toEqual(["b", "a"]);
    expect(result.witnesses).not.toBe(witnesses);
  });
});

describe("runCheck — the only helper that invokes a Check", () => {
  const LABELS = ["a", "b"];
  const delta: ChainDelta = { pre: snap({}), post: snap({}) };
  const params: CheckParams = { packageId: PKG, attackerAddress: "0xatk" };
  const evidence: CheckEvidence = { attackTransactions: [] };

  it("passes the exact evidence object through as the third argument", () => {
    let seen: CheckEvidence | undefined;
    const check: Check = (_delta, _params, ev) => {
      seen = ev;
      return { witnesses: [] };
    };
    runCheck(check, LABELS, delta, params, evidence);
    expect(seen).toBe(evidence);
  });

  it("applies the authoring guard to the check's return value", () => {
    const check: Check = () => ({ witnesses: ["b", "a"] });
    expect(runCheck(check, LABELS, delta, params, evidence)).toEqual({
      witnesses: ["a", "b"],
    });
  });

  it("rejects malformed check output through the same shared path", () => {
    const check = (() => ({ witnesses: ["nope"] })) as unknown as Check;
    expect(() => runCheck(check, LABELS, delta, params, evidence)).toThrow();

    const badShape = (() => true) as unknown as Check;
    expect(() => runCheck(badShape, LABELS, delta, params, evidence)).toThrow();
  });
});

describe("successfulMoveEvents — attack-phase evidence reader", () => {
  const EVENT_TYPE = `${PKG}::pool::Redemption`;
  const paddedType = () => {
    const hex = "abc".padStart(64, "0");
    return `0x${hex}::pool::Redemption`;
  };

  const tx = (
    status: "success" | "failure",
    events: { type: string; json: unknown }[],
  ): AttackTransactionEvidence => ({
    digest: `d-${status}-${events.length}`,
    status,
    events,
  });

  it("returns only events from successful transactions, preserving order", () => {
    const evidence: CheckEvidence = {
      attackTransactions: [
        tx("success", [{ type: EVENT_TYPE, json: { n: 1 } }]),
        tx("failure", [{ type: EVENT_TYPE, json: { n: 2 } }]),
        tx("success", [{ type: EVENT_TYPE, json: { n: 3 } }, { type: EVENT_TYPE, json: { n: 4 } }]),
      ],
    };
    expect(successfulMoveEvents(evidence, EVENT_TYPE).map((e) => (e.json as { n: number }).n)).toEqual([
      1, 3, 4,
    ]);
  });

  it("matches event types whose package address differs only by short/padded canonical form", () => {
    const evidence: CheckEvidence = {
      attackTransactions: [tx("success", [{ type: paddedType(), json: { n: 1 } }])],
    };
    expect(successfulMoveEvents(evidence, EVENT_TYPE)).toHaveLength(1);
  });

  it("returns an empty array for a missing type", () => {
    const evidence: CheckEvidence = {
      attackTransactions: [tx("success", [{ type: EVENT_TYPE, json: {} }])],
    };
    expect(successfulMoveEvents(evidence, `${PKG}::pool::OtherEvent`)).toEqual([]);
  });

  it("returns an empty array when the only matching events are in a failed transaction", () => {
    const evidence: CheckEvidence = {
      attackTransactions: [tx("failure", [{ type: EVENT_TYPE, json: {} }])],
    };
    expect(successfulMoveEvents(evidence, EVENT_TYPE)).toEqual([]);
  });
});
