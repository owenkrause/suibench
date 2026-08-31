// Snapshot-pure success predicate for `harvest_min_return_self_reported`.
//
// The operator (attacker) drains the whole vault via a fabricated returned_amount
// and keeps the funds. They deposited nothing (a depositor funded the vault), so
// an ASSET gain >= 300 means they took depositor funds past the min-return floor.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "self-reported-return" as const;

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const witnessed = balanceGained(delta, params.attackerAddress, ASSET) >= 300n;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
