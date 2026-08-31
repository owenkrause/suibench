import { describe, expect, it } from "vitest";
import type { ChainDelta, CheckEvidence } from "core";
import { check } from "./check.js";

const PACKAGE = "0xabc";
const ATTACKER = "0xa11ce";
const ORACLE = `${PACKAGE}::oracle::Oracle`;
const EVENT = `${PACKAGE}::oracle::OracleUpdated`;
const LABEL = "missing-authorization-update-v2-discards-its-permission-check";

function delta(
  pre: Record<string, unknown> = { price: "0", twap_price: "0" },
  post: Record<string, unknown> = {
    price: "133713371338",
    twap_price: "133713371339",
  },
): ChainDelta {
  const objects = (fields: Record<string, unknown>) => ({
    ownerOf: { oracle: null },
    byId: {
      oracle: {
        owner: { Shared: { initial_shared_version: "1" } },
        type: ORACLE,
        fields,
      },
    },
  });
  return {
    pre: { balances: { byAddress: {} }, objects: objects(pre) },
    post: { balances: { byAddress: {} }, objects: objects(post) },
  };
}

function evidence(
  json: unknown,
  status: "success" | "failure" = "success",
  eventType: string = EVENT,
): CheckEvidence {
  return {
    attackTransactions: [{ digest: "update", status, events: [{ type: eventType, json }] }],
  };
}

const alternateUpdate = {
  actor: ATTACKER,
  previous_price: "0",
  previous_twap_price: "0",
  new_price: "133713371338",
  new_twap_price: "133713371339",
};

describe("typus_discarded_auth checker", () => {
  it("witnesses the attacker's successful arbitrary Oracle update", () => {
    expect(
      check(
        delta(),
        { packageId: PACKAGE, attackerAddress: ATTACKER },
        evidence(alternateUpdate),
      ).witnesses,
    ).toEqual([LABEL]);
  });

  it.each([
    {
      name: "a failed update event",
      attackEvidence: evidence(alternateUpdate, "failure"),
      attackDelta: delta(),
    },
    {
      name: "an update event from another package",
      attackEvidence: evidence(alternateUpdate, "success", "0xdef::oracle::OracleUpdated"),
      attackDelta: delta(),
    },
    {
      name: "an update event emitted by another actor",
      attackEvidence: evidence({ ...alternateUpdate, actor: "0xdead" }),
      attackDelta: delta(),
    },
    {
      name: "an event whose new values do not match the final Oracle",
      attackEvidence: evidence(alternateUpdate),
      attackDelta: delta(undefined, { price: "2", twap_price: "3" }),
    },
    {
      name: "an event whose previous values do not match the initial Oracle",
      attackEvidence: evidence({
        ...alternateUpdate,
        previous_price: "42",
        previous_twap_price: "42",
      }),
      attackDelta: delta(),
    },
    {
      name: "an event with no Oracle value change",
      attackEvidence: evidence({
        ...alternateUpdate,
        new_price: "0",
        new_twap_price: "0",
      }),
      attackDelta: delta({ price: "0", twap_price: "0" }, { price: "0", twap_price: "0" }),
    },
    {
      name: "malformed event fields",
      attackEvidence: evidence({ ...alternateUpdate, new_price: "not-a-number" }),
      attackDelta: delta(),
    },
  ])("rejects $name", ({ attackEvidence, attackDelta }) => {
    expect(
      check(
        attackDelta,
        { packageId: PACKAGE, attackerAddress: ATTACKER },
        attackEvidence,
      ).witnesses,
    ).toEqual([]);
  });
});
