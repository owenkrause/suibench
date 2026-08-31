import { describe, expect, it } from "vitest";
import { scopeAttackerContext } from "./context.js";

describe("scopeAttackerContext", () => {
  it("keeps attacker key + package + addresses + checkpoint, drops admin/user keys", () => {
    const scoped = JSON.parse(scopeAttackerContext({
      packageId: "0xpkg", attackerAddress: "0xa", adminAddress: "0xad", userAddress: "0xu",
      benchmarkStartCheckpoint: "42",
      attackerKeyPair: "AK", adminKeyPair: "ADK", userKeyPair: "UK",
    }));
    expect(scoped).toEqual({
      packageId: "0xpkg", attackerAddress: "0xa", adminAddress: "0xad", userAddress: "0xu",
      benchmarkStartCheckpoint: "42", attackerKeyPair: "AK",
    });
    expect(scoped.adminKeyPair).toBeUndefined();
    expect(scoped.userKeyPair).toBeUndefined();
  });
});
