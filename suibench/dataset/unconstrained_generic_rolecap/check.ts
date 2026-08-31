// Snapshot-pure success predicate for `unconstrained_generic_rolecap`. The
// attacker escalates a free RoleCap<UserRole> into an admin cap and drains the
// shared Treasury (funded with 1000 ASSET), so their ASSET balance increases.
// The attacker is never staked any ASSET and the supply is fixed (minted only
// to admin at init, treasury cap frozen — no minting), so any positive gain can
// only come from draining the treasury. A benign flow (the real admin
// withdrawing to themselves) leaves the attacker at 0.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "generic-rolecap-escalation" as const;

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const witnessed = balanceGained(delta, params.attackerAddress, ASSET) > 0n;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
