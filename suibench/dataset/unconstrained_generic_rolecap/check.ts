// Snapshot-pure success predicate for `unconstrained_generic_rolecap`. The
// attacker escalates a free RoleCap<UserRole> into an admin cap and drains the
// shared Treasury (funded with 1000 ASSET), so their ASSET balance jumps by
// ~1000. The attacker is never staked any ASSET and the supply is fixed
// (minted only to admin at init, treasury cap frozen — no minting), so any
// gain can only come from draining the treasury. A benign flow (the real
// admin withdrawing to themselves) leaves the attacker at 0. Threshold 300
// sits far above any benign attacker flow (which is 0).
import { type Check, balanceGained } from "core";

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  return balanceGained(delta, params.attackerAddress, ASSET) >= 300n;
};
