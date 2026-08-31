import { describe, expect, it } from "vitest";
import type { ChainDelta } from "core";
import { check } from "./check.js";

const PACKAGE = "0xpkg";
const ATTACKER = "0xattacker";
const ASSET = `${PACKAGE}::asset::ASSET`;
const OTHER_ASSET = `${PACKAGE}::asset::OTHER`;

function deltaWithAttackerBalances(
  preBalances: Record<string, bigint>,
  postBalances: Record<string, bigint>,
): ChainDelta {
  return {
    pre: {
      balances: { byAddress: { [ATTACKER]: preBalances } },
      objects: { ownerOf: {}, byId: {} },
    },
    post: {
      balances: { byAddress: { [ATTACKER]: postBalances } },
      objects: { ownerOf: {}, byId: {} },
    },
  };
}

function witnesses(
  preBalances: Record<string, bigint>,
  postBalances: Record<string, bigint>,
): readonly string[] {
  return check(
    deltaWithAttackerBalances(preBalances, postBalances),
    { packageId: PACKAGE, attackerAddress: ATTACKER },
    { attackTransactions: [] },
  ).witnesses;
}

describe("generic-rolecap-escalation checker", () => {
  it("witnesses any positive attacker ASSET gain, including 299", () => {
    expect(witnesses({ [ASSET]: 1000n }, { [ASSET]: 1299n })).toEqual([
      "generic-rolecap-escalation",
    ]);
  });

  it("does not witness a zero ASSET gain despite a nonzero pre-balance", () => {
    expect(witnesses({ [ASSET]: 1000n }, { [ASSET]: 1000n })).toEqual([]);
  });

  it("does not witness an ASSET loss", () => {
    expect(witnesses({ [ASSET]: 1000n }, { [ASSET]: 999n })).toEqual([]);
  });

  it("does not witness a gain in an unrelated asset type", () => {
    expect(
      witnesses(
        { [ASSET]: 1000n },
        { [ASSET]: 1000n, [OTHER_ASSET]: 299n },
      ),
    ).toEqual([]);
  });
});
