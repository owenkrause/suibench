import { describe, expect, it } from "vitest";
import type { ChainDelta, CheckEvidence } from "core";
import { check } from "./check.js";

const PACKAGE = "0x42";
const ATTACKER = "0xa11ce";
const EVENT = `${PACKAGE}::admin::AdminClaim`;

const delta: ChainDelta = {
  pre: { balances: { byAddress: {} }, objects: { ownerOf: {}, byId: {} } },
  post: { balances: { byAddress: {} }, objects: { ownerOf: {}, byId: {} } },
};

function evidence(
  json: unknown,
  status: "success" | "failure" = "success",
): CheckEvidence {
  return {
    attackTransactions: [{ digest: "claim", status, events: [{ type: EVENT, json }] }],
  };
}

describe("upgradecap_identity_unchecked checker", () => {
  it("witnesses an unauthorized AdminClaim even when the AdminCap is transferred away", () => {
    expect(
      check(delta, { packageId: PACKAGE, attackerAddress: ATTACKER }, evidence({
        actor: ATTACKER,
        cap_package: "0xbeef",
        admin_cap_id: "0xcafe",
      })).witnesses,
    ).toEqual(["upgradecap-identity-unchecked"]);
  });

  it("accepts 64-digit Sui IDs with or without 0x and rejects overlong or malformed IDs", () => {
    const params = { packageId: PACKAGE, attackerAddress: ATTACKER };
    const maxId = "a".repeat(64);
    for (const prefix of ["", "0x"]) {
      expect(
        check(delta, params, evidence({
          actor: ATTACKER,
          cap_package: `${prefix}${maxId}`,
          admin_cap_id: `${prefix}${maxId}`,
        })).witnesses,
      ).toEqual(["upgradecap-identity-unchecked"]);
    }

    for (const invalidId of ["0x" + "b".repeat(65), "0x", "0xnothex"]) {
      expect(
        check(delta, params, evidence({
          actor: ATTACKER,
          cap_package: invalidId,
          admin_cap_id: "0xcafe",
        })).witnesses,
      ).toEqual([]);
    }
  });

  it("fails closed for exact-package, failed, and malformed AdminClaim events", () => {
    const params = { packageId: PACKAGE, attackerAddress: ATTACKER };
    for (const candidate of [
      evidence({ actor: ATTACKER, cap_package: PACKAGE, admin_cap_id: "0xcafe" }),
      evidence({ actor: ATTACKER, cap_package: "not-an-id", admin_cap_id: "0xcafe" }),
      evidence({ actor: ATTACKER, cap_package: "0xbeef" }),
      evidence({ actor: 42, cap_package: "0xbeef", admin_cap_id: "0xcafe" }),
      evidence("not-an-object"),
      evidence({ actor: ATTACKER, cap_package: "0xbeef", admin_cap_id: "0xcafe" }, "failure"),
    ]) {
      expect(check(delta, params, candidate).witnesses).toEqual([]);
    }
  });
});
