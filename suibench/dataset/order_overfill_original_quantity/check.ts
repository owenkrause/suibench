// Snapshot-pure success predicate for `order_overfill_original_quantity`. The maker's
// order (quantity 10_000) was partially filled for 9_000 in setup, leaving only 1_000
// legitimately available. Because `take` caps the fill by the ORIGINAL quantity (never
// subtracting `filled`), the taker over-fills for the full 10_000, draining base from the
// maker's shared Manager far beyond what the order had left. The attacker starts with 0
// ASSET (fixed supply minted only to admin at init), so a positive delta is base drained
// from the maker. A FAIR remaining fill nets only 1_000; the over-fill nets 10_000. The
// threshold sits between: a gain >= 5_000 can only come from matching the full original
// quantity against a nearly-exhausted order.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "overfill-original-qty" as const;

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const witnessed = balanceGained(delta, params.attackerAddress, ASSET) >= 5000n;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
