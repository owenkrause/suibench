// Snapshot-pure success predicate for `reward_index_uninitialized`.
//
// The attacker stakes 100 ASSET AFTER the pool has accrued its rewards, then
// claims. Because their last_index defaults to 0, they collect a share of the
// whole reward history (staked 100, claims ~1000), netting ~+900 ASSET. A late
// staker on a correct contract nets <= 0 (they earned nothing before joining).
// Supply is fixed and the attacker only ever received their 100 stake, so a gain
// >= 500 means they siphoned rewards accrued before they staked.
import { type Check, balanceGained } from "core";

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  return balanceGained(delta, params.attackerAddress, ASSET) >= 500n;
};
