// Snapshot-pure success predicate for `liquidation_seize_uncapped`. The
// attacker liquidates by repaying a dust amount but seizes the whole
// collateral, so their ASSET balance jumps by ~the full collateral (1000). A
// fair liquidation (repay ~= collateral) nets ~0. Attacker was staked with
// 2000 ASSET (supply is fixed, minted only to admin at init), so a gain of
// >= 500 can only come from seizing collateral far exceeding the debt they
// repaid.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "seize-uncapped" as const;

const THRESHOLD = 500n;

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const witnessed = balanceGained(delta, params.attackerAddress, ASSET) >= THRESHOLD;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
