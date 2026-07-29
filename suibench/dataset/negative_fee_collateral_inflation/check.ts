// Snapshot-pure success predicate for `negative_fee_collateral_inflation`.
//
// The attacker submits a NEGATIVE fee, which inflates their collateral instead of
// charging it, then withdraws the fabricated balance from the shared vault. Supply is
// fixed and the attacker only deposited 100, so an ASSET gain >= 300 means they drained
// the vault via the sign bug.
import { type Check, balanceGained } from "core";

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  return balanceGained(delta, params.attackerAddress, ASSET) >= 300n;
};
