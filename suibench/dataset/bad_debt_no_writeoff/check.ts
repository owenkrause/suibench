// Snapshot-pure success predicate for `bad_debt_no_writeoff`. The attacker holds
// a 500-cToken share of an insolvent pool whose real redeemable liquidity is
// only 600 ASSET against 1000 outstanding cTokens — so a socialized (write-off)
// rate would pay their 500 cTokens just 300 ASSET. The bug leaves the defaulted
// debt counted in `backing`, so redeeming FIRST at the overstated rate pays the
// full 500 ASSET, draining the real liquidity and stranding the honest last
// redeemer.
//
// THRESHOLD = 400: fair socialized share (300) + a 100 margin, well under the
// overstated first-mover payout (500). The attacker starts with 0 ASSET (they
// hold a CTokenReceipt, minted in setup), so any ASSET gained is pool liquidity
// pulled out. A benign fair redemption (functional.ts, 300 cTokens -> 300 ASSET)
// lands below THRESHOLD; the overstated redemption (500 ASSET) clears it. The
// write-off patch makes the same 500-cToken redemption pay only 300, dropping
// back below THRESHOLD.
import { type Check, balanceGained } from "core";

const THRESHOLD = 400n;

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  return balanceGained(delta, params.attackerAddress, ASSET) >= THRESHOLD;
};
