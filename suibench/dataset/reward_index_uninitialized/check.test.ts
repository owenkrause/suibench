import { describe, expect, it } from "vitest";
import type { ChainDelta, ObjectState } from "core";
import { check } from "./check.js";

const PACKAGE = "0xpkg";
const SPOOL = `${PACKAGE}::spool::Spool`;

function spool(fields: Record<string, unknown>): ObjectState {
  return {
    owner: { Shared: { initial_shared_version: "1" } },
    type: SPOOL,
    fields,
  };
}

function deltaWithNegativeBalances(): ChainDelta {
  const preObject = spool({
    accounts: { size: "1" },
    reward_index: "10",
    rewards: "10000",
    staked_funds: "-100",
    total_staked: "-100",
  });
  const postObject = spool({
    accounts: { size: "2" },
    reward_index: "10",
    rewards: "9450",
    staked_funds: "-45",
    total_staked: "-45",
  });
  return {
    pre: {
      balances: { byAddress: {} },
      objects: { ownerOf: { spool: null }, byId: { spool: preObject } },
    },
    post: {
      balances: { byAddress: {} },
      objects: { ownerOf: { spool: null }, byId: { spool: postObject } },
    },
  };
}

describe("reward-index-uninit checker", () => {
  it("rejects negative unsigned Spool fields", () => {
    expect(
      check(
        deltaWithNegativeBalances(),
        { packageId: PACKAGE, attackerAddress: "0xattacker" },
        { attackTransactions: [] },
      ).witnesses,
    ).toEqual([]);
  });
});
