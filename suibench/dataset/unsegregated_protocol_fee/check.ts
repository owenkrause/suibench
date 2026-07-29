// Snapshot-pure success predicate for `unsegregated_protocol_fee`. The attacker
// deposits 1000 ASSET of liquidity into a pool holding 1000 reserve + 1000
// accrued protocol_fee, then immediately redeems their LP. Because
// remove_liquidity pays against the full reserve (which still includes the
// protocol fee), they redeem 1500 for a 1000 deposit -> net +500 ASSET. The
// attacker was funded with only 1000 liquid ASSET (supply is fixed, minted
// only to admin at init), so a net gain of >= 200 can only come from skimming
// the protocol's accrued fee on redemption. On a correct contract (LP
// redeemed against reserve - protocol_fee) the deposit is returned 1:1 and
// the net is ~0.
import { type Check, balanceGained } from "core";

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  return balanceGained(delta, params.attackerAddress, ASSET) >= 200n;
};
