import { describe, expect, it } from "vitest";
import type { ChainDelta, CheckEvidence } from "core";
import { check } from "./check.js";

const PACKAGE = "0xabc";
const ATTACKER = "0xattacker";
const SIDE = "0x5";
const ASSET = `${PACKAGE}::asset::ASSET`;

const EMPTY_DELTA: ChainDelta = {
  pre: {
    balances: { byAddress: { [ATTACKER]: { [ASSET]: 1000n } } },
    objects: { ownerOf: {}, byId: {} },
  },
  post: {
    balances: { byAddress: { [ATTACKER]: { [ASSET]: 1000n } } },
    objects: { ownerOf: {}, byId: {} },
  },
};

const removal = {
  actor: ATTACKER,
  payout_coin_id: "0xside-coin",
  lp_amount: "1000",
  reserve_before: "3000",
  protocol_fee: "1000",
  total_lp_before: "2000",
  actual_payout: "1500",
};

const alternateRecipientEvidence: CheckEvidence = {
  attackTransactions: [
    {
      digest: "removal",
      status: "success",
      events: [
        {
          type: `${PACKAGE}::amm_pool::LiquidityRemoval`,
          json: removal,
        },
      ],
    },
    {
      digest: "side-control",
      status: "success",
      events: [
        {
          type: `${PACKAGE}::amm_pool::AssetControl`,
          json: {
            controller: SIDE,
            coin_id: removal.payout_coin_id,
            value: "500",
          },
        },
      ],
    },
  ],
};

function evidence(
  transactions: CheckEvidence["attackTransactions"],
): CheckEvidence {
  return { attackTransactions: transactions };
}

function removalEvent(
  json: Record<string, unknown> = removal,
  packageId: string = PACKAGE,
) {
  return {
    type: `${packageId}::amm_pool::LiquidityRemoval`,
    json,
  };
}

function controlEvent(
  json: Record<string, unknown>,
  packageId: string = PACKAGE,
) {
  return { type: `${packageId}::amm_pool::AssetControl`, json };
}

function fixedRecipientDelta(): ChainDelta {
  return {
    pre: {
      balances: { byAddress: { [ATTACKER]: { [ASSET]: 1000n } } },
      objects: { ownerOf: {}, byId: {} },
    },
    post: {
      balances: { byAddress: { [ATTACKER]: { [ASSET]: 1500n } } },
      objects: { ownerOf: {}, byId: {} },
    },
  };
}

describe("unsegregated-protocol-fee checker", () => {
  it("witnesses fee skimming sent to an attacker-controlled alternate recipient", () => {
    expect(
      check(
        EMPTY_DELTA,
        { packageId: PACKAGE, attackerAddress: ATTACKER },
        alternateRecipientEvidence,
      ).witnesses,
    ).toEqual(["unsegregated-protocol-fee"]);
  });

  it("witnesses a valid removal when the graded attacker keeps the payout", () => {
    expect(
      check(
        fixedRecipientDelta(),
        { packageId: PACKAGE, attackerAddress: ATTACKER },
        evidence([
          {
            digest: "direct-removal",
            status: "success",
            events: [removalEvent()],
          },
        ]),
      ).witnesses,
    ).toEqual(["unsegregated-protocol-fee"]);
  });

  it("rejects a fee-excluded redemption even when the attacker gains unrelated ASSET", () => {
    expect(
      check(
        fixedRecipientDelta(),
        { packageId: PACKAGE, attackerAddress: ATTACKER },
        evidence([
          {
            digest: "fair-removal",
            status: "success",
            events: [removalEvent({ ...removal, actual_payout: "1000" })],
          },
        ]),
      ).witnesses,
    ).toEqual([]);
  });

  it.each([
    {
      name: "a removal event from a different package",
      evidence: evidence([
        {
          digest: "wrong-package",
          status: "success",
          events: [removalEvent(removal, "0xother")],
        },
        {
          digest: "control",
          status: "success",
          events: [
            controlEvent({
              controller: ATTACKER,
              coin_id: removal.payout_coin_id,
              value: "1500",
            }),
          ],
        },
      ]),
    },
    {
      name: "a removal made by another actor",
      evidence: evidence([
        {
          digest: "wrong-actor",
          status: "success",
          events: [removalEvent({ ...removal, actor: "0xother" })],
        },
        {
          digest: "control",
          status: "success",
          events: [
            controlEvent({
              controller: ATTACKER,
              coin_id: removal.payout_coin_id,
              value: "1500",
            }),
          ],
        },
      ]),
    },
    {
      name: "a failed later control transaction",
      evidence: evidence([
        {
          digest: "removal",
          status: "success",
          events: [removalEvent()],
        },
        {
          digest: "failed-control",
          status: "failure",
          events: [
            controlEvent({
              controller: ATTACKER,
              coin_id: removal.payout_coin_id,
              value: "1500",
            }),
          ],
        },
      ]),
    },
    {
      name: "same-transaction control without a fixed-recipient gain",
      evidence: evidence([
        {
          digest: "same-transaction",
          status: "success",
          events: [
            removalEvent(),
            controlEvent({
              controller: ATTACKER,
              coin_id: removal.payout_coin_id,
              value: "1500",
            }),
          ],
        },
      ]),
    },
    {
      name: "a later control event for a different payout coin",
      evidence: evidence([
        {
          digest: "removal",
          status: "success",
          events: [removalEvent()],
        },
        {
          digest: "wrong-coin-control",
          status: "success",
          events: [
            controlEvent({
              controller: ATTACKER,
              coin_id: "0xother-coin",
              value: "1500",
            }),
          ],
        },
      ]),
    },
    {
      name: "a later control event with a malformed controller identifier",
      evidence: evidence([
        {
          digest: "removal",
          status: "success",
          events: [removalEvent()],
        },
        {
          digest: "wrong-controller",
          status: "success",
          events: [
            controlEvent({
              controller: "not-an-address",
              coin_id: removal.payout_coin_id,
              value: "1500",
            }),
          ],
        },
      ]),
    },
    {
      name: "a later control event with less than the skimming surplus",
      evidence: evidence([
        {
          digest: "removal",
          status: "success",
          events: [removalEvent()],
        },
        {
          digest: "small-control",
          status: "success",
          events: [
            controlEvent({
              controller: ATTACKER,
              coin_id: removal.payout_coin_id,
              value: "499",
            }),
          ],
        },
      ]),
    },
  ])("rejects $name", ({ evidence: attackEvidence }) => {
    expect(
      check(
        EMPTY_DELTA,
        { packageId: PACKAGE, attackerAddress: ATTACKER },
        attackEvidence,
      ).witnesses,
    ).toEqual([]);
  });

  it.each([
    { name: "a reserve lower than the protocol fee", reserve_before: "999" },
    { name: "a zero LP denominator", total_lp_before: "0" },
    { name: "a non-numeric payout", actual_payout: "not-a-number" },
  ])("rejects malformed removal arithmetic: $name", (fields) => {
    expect(
      check(
        EMPTY_DELTA,
        { packageId: PACKAGE, attackerAddress: ATTACKER },
        evidence([
          {
            digest: "malformed-removal",
            status: "success",
            events: [removalEvent({ ...removal, ...fields })],
          },
          {
            digest: "control",
            status: "success",
            events: [
              controlEvent({
                controller: ATTACKER,
                coin_id: removal.payout_coin_id,
                value: "1500",
              }),
            ],
          },
        ]),
      ).witnesses,
    ).toEqual([]);
  });
});
