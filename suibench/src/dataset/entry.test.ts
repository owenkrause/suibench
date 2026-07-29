import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import type {
  ChainSnapshot,
  ChainDelta,
  ObjectState,
  VictimOutcome,
  CheckParams,
} from "core";
import { loadEntry, loadCheck } from "./entry.js";
import { parseManifest } from "./manifest.js";

const DATASET = resolve(import.meta.dirname, "../../dataset");

const PKG = "0xpkg";
const ATTACKER = "0xattacker";
const ADMIN = "0xadmin";
const USER = "0xuser";

/** Hand-build a snapshot from balances, owned objects, and an optional victim. */
function snap(
  balances: Record<string, Record<string, bigint>>,
  objects: Record<string, ObjectState> = {},
  victim?: VictimOutcome,
): ChainSnapshot {
  const ownerOf: Record<string, string | null> = {};
  for (const [id, o] of Object.entries(objects)) ownerOf[id] = o.owner;
  return {
    balances: { byAddress: balances },
    objects: { ownerOf, byId: objects },
    events: { events: [] },
    ...(victim ? { victim } : {}),
  };
}

describe("manifest validation", () => {
  it("rejects a duplicate vuln id", () => {
    const raw = JSON.stringify({
      vulns: [
        { id: "a", module: "m", title: "t", severity: "high", root_cause: "r" },
        { id: "a", module: "m", title: "t2", severity: "low", root_cause: "r" },
      ],
    });
    expect(() => parseManifest(raw, "x")).toThrow(/duplicate vuln id/);
  });

  it("rejects an invalid severity", () => {
    const raw = JSON.stringify({
      vulns: [
        { id: "a", module: "m", title: "t", severity: "sev", root_cause: "r" },
      ],
    });
    expect(() => parseManifest(raw, "x")).toThrow(/invalid severity/);
  });
});

describe("loadEntry — the 3 migrated entries load, validate, and map cleanly", () => {
  const entries = [
    "capability_leak",
    "unchecked_arithmetic",
    "deepbook_critbit_dos",
  ];

  for (const name of entries) {
    it(`${name}: manifest + exploits/patches map to real ids; confirmed-tier`, () => {
      const e = loadEntry(resolve(DATASET, name));
      expect(e.tier).toBe("confirmed");
      expect(e.checkPath).not.toBeNull();
      const ids = new Set(e.manifest.vulns.map((v) => v.id));
      for (const id of Object.keys(e.exploits)) expect(ids.has(id)).toBe(true);
      for (const id of Object.keys(e.patches)) expect(ids.has(id)).toBe(true);
      // every declared exploit/patch id resolved to a file/dir
      for (const v of e.manifest.vulns) {
        if (v.exploit) expect(e.exploits[v.id]).toBeDefined();
        if (v.patch) expect(e.patches[v.id]).toBeDefined();
      }
    });
  }

  it("unchecked_arithmetic ships a setup phase; deepbook ships a victim phase", () => {
    const ua = loadEntry(resolve(DATASET, "unchecked_arithmetic"));
    expect(ua.harness.setup).toBeDefined();
    const db = loadEntry(resolve(DATASET, "deepbook_critbit_dos"));
    expect(db.harness.victim).toBeDefined();
  });
});

// The core assertion of Task 9: each migrated check COMPILES (imports cleanly)
// and is SNAPSHOT-PURE — a pure `(ChainDelta, params) => boolean` decided from a
// hand-built ChainDelta, with no live client.
describe("migrated checks are snapshot-pure against a hand-built ChainDelta", () => {
  const ADMIN_CAP: ObjectState = {
    owner: "",
    type: `${PKG}::vault::AdminCap`,
    fields: {},
  };
  const cap = (owner: string): ObjectState => ({ ...ADMIN_CAP, owner });

  it("capability_leak: true iff attacker AND admin both hold an AdminCap", async () => {
    const e = loadEntry(resolve(DATASET, "capability_leak"));
    const check = await loadCheck(e);
    const params: CheckParams = {
      packageId: PKG,
      attackerAddress: ATTACKER,
      adminAddress: ADMIN,
    };
    const pre: ChainDelta["pre"] = snap({}, { admin: cap(ADMIN) });

    // fresh mint: attacker + admin both hold a cap -> true
    const minted: ChainDelta = {
      pre,
      post: snap({}, { admin: cap(ADMIN), attacker: cap(ATTACKER) }),
    };
    expect(check(minted, params)).toBe(true);

    // transfer cheat: only attacker holds the (single) cap -> false
    const transferred: ChainDelta = {
      pre,
      post: snap({}, { attacker: cap(ATTACKER) }),
    };
    expect(check(transferred, params)).toBe(false);
  });

  it("unchecked_arithmetic: true iff attacker netted ~D AND victim ShareToken.shares == 0", async () => {
    const e = loadEntry(resolve(DATASET, "unchecked_arithmetic"));
    const check = await loadCheck(e);
    const ASSET = `${PKG}::asset::ASSET`;
    const params: CheckParams = {
      packageId: PKG,
      attackerAddress: ATTACKER,
      userAddress: USER,
    };
    const share = (shares: string): ObjectState => ({
      owner: USER,
      type: `${PKG}::reward_pool::ShareToken`,
      fields: { shares },
    });
    const pre = snap({ [ATTACKER]: { [ASSET]: 0n } });

    // bug: attacker +100000 and victim holds a 0-share token -> true
    expect(
      check(
        {
          pre,
          post: snap({ [ATTACKER]: { [ASSET]: 100_000n } }, { s: share("0") }),
        },
        params,
      ),
    ).toBe(true);

    // patched share math: victim's token has nonzero shares -> false
    expect(
      check(
        {
          pre,
          post: snap({ [ATTACKER]: { [ASSET]: 100_000n } }, { s: share("5") }),
        },
        params,
      ),
    ).toBe(false);

    // attacker didn't net the deposit -> false
    expect(
      check(
        {
          pre,
          post: snap({ [ATTACKER]: { [ASSET]: 10n } }, { s: share("0") }),
        },
        params,
      ),
    ).toBe(false);
  });

  it("deepbook_critbit_dos: true iff the victim op did NOT succeed", async () => {
    const e = loadEntry(resolve(DATASET, "deepbook_critbit_dos"));
    const check = await loadCheck(e);
    const params: CheckParams = { packageId: PKG, attackerAddress: ATTACKER };
    const pre = snap({});

    // bricked: victim aborts -> exploit succeeded -> true
    expect(
      check(
        { pre, post: snap({}, {}, { status: "abort", message: "oob" }) },
        params,
      ),
    ).toBe(true);

    // patched: victim traversal completes -> false
    expect(
      check(
        { pre, post: snap({}, {}, { status: "success", message: null }) },
        params,
      ),
    ).toBe(false);
  });
});
