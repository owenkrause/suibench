// Snapshot-pure success predicate for `flashloan_receipt_wrong_order`.
//
// The attacker flash-borrows 1000 ASSET from the victim order V and repays it
// into their OWN order A (the receipt's order_id is discarded), then withdraws
// A. The victim's order is drained and the attacker gains ~+1010 ASSET. Supply
// is fixed and the attacker was only staked ~20, so a gain >= 500 means they
// siphoned V's funds.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "receipt-wrong-order" as const;

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const witnessed = balanceGained(delta, params.attackerAddress, ASSET) >= 500n;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
