// Snapshot-pure success predicate for `harvest_min_return_self_reported`.
//
// The operator (attacker) drains the whole vault via a fabricated returned_amount
// and keeps the funds. They deposited nothing (a depositor funded the vault), so
// an ASSET gain >= 300 means they took depositor funds past the min-return floor.
import { type Check, balanceGained } from "core";

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  return balanceGained(delta, params.attackerAddress, ASSET) >= 300n;
};
