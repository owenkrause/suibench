// Snapshot-pure success predicate for `redeem_burn_before_rate`.
//
// The attack episode is stake 1000 ASSET (minting 1000 shares) then redeem those
// 1000 shares. The pre snapshot is taken with the attacker still holding their
// full 1000 ASSET, so balanceGained measures NET profit across stake+redeem.
// Because redeem shrinks total_hawal before pricing the payout, redeeming 1000
// shares pays 2000 ASSET — a 2x over-redemption that drains the admin's backing —
// for a net of +1000. A correct (fair-rate) redeem returns exactly the 1000
// staked, netting 0. Supply is fixed and the attacker never minted, so a net gain
// >= 500 means they over-redeemed at the other holders' expense.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "burn-before-rate" as const;

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const witnessed = balanceGained(delta, params.attackerAddress, ASSET) >= 500n;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
