// Snapshot-pure success predicate for `flashloan_receipt_droppable`.
//
// The attacker flash-borrows the full pool liquidity (L=1000 ASSET) and,
// because FlashLoanReceipt has `drop`, lets the receipt be discarded instead of
// repaying — so the borrowed coin is kept and the pool is drained. The
// attacker starts with 0 ASSET (the pool is seeded only from the admin's fixed
// supply, minted only at init), so their post-attack ASSET balance is exactly
// the drained amount. A benign flash loan (borrow + repay same tx) nets ~0.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "receipt-droppable" as const;

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const witnessed = balanceGained(delta, params.attackerAddress, ASSET) >= 500n;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
