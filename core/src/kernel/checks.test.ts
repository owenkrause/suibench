import { describe, it, expect } from "vitest";
import type {
  ChainSnapshot,
  ChainDelta,
  ObjectState,
  Exploit,
} from "./types.js";
import {
  balanceAt,
  balanceGained,
  ownedObjects,
  ownedObjectFields,
  fieldAsBigInt,
  type Check,
  runCheck,
} from "./checks.js";

const PKG = "0x0abc";

/** Build a snapshot from per-address per-coin balances and (optionally) objects. */
function snap(
  balances: Record<string, Record<string, bigint>>,
  objects: Record<string, ObjectState> = {},
): ChainSnapshot {
  const ownerOf: Record<string, string | null> = {};
  for (const [id, o] of Object.entries(objects)) ownerOf[id] = o.owner;
  return {
    balances: { byAddress: balances },
    objects: { ownerOf, byId: objects },
    events: { events: [] },
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
    owner,
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

describe("fieldAsBigInt — numeric Move field as bigint", () => {
  it("reads string / number / bigint; null on absent or non-numeric", () => {
    expect(fieldAsBigInt({ shares: "0" }, "shares")).toBe(0n);
    expect(fieldAsBigInt({ shares: 42 }, "shares")).toBe(42n);
    expect(fieldAsBigInt({ shares: 7n }, "shares")).toBe(7n);
    expect(fieldAsBigInt({}, "shares")).toBeNull();
    expect(fieldAsBigInt({ shares: { nested: true } }, "shares")).toBeNull();
  });
});

describe("runCheck — lifts a boolean predicate into a Verdict with committed proof", () => {
  const exploit: Exploit = {
    finding: {
      id: "vuln-001",
      module: "reward_pool",
      severity: "critical",
      title: "share truncation",
      description: "d",
    },
    script: { path: "exploit-001.mts", contents: "" },
  };
  const params = { packageId: PKG, attackerAddress: "0xatk" };
  const ASSET = `${PKG}::asset::ASSET`;

  // A minimal effect-based check, injected exactly as a corpus entry would.
  const gained400: Check = (delta, p) =>
    balanceGained(delta, p.attackerAddress, ASSET) >= 400n;

  it("a passing check yields confirmed carrying the POST snapshot as proof", () => {
    const delta: ChainDelta = {
      pre: snap({ "0xatk": { [ASSET]: 0n } }),
      post: snap({ "0xatk": { [ASSET]: 500n } }),
    };
    const v = runCheck(gained400, delta, params, exploit);
    expect(v.kind).toBe("confirmed");
    if (v.kind === "confirmed") expect(v.proof).toBe(delta.post);
  });

  it("a failing check yields refuted", () => {
    const delta: ChainDelta = {
      pre: snap({ "0xatk": { [ASSET]: 0n } }),
      post: snap({ "0xatk": { [ASSET]: 100n } }),
    };
    const v = runCheck(gained400, delta, params, exploit);
    expect(v.kind).toBe("refuted");
  });
});
