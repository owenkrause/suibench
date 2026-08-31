// Snapshot-pure success predicate for `capability_leak`.
//
// The bug MINTS a fresh AdminCap to any caller. `init` transfers exactly ONE
// AdminCap to the deployer (the container publishes as admin), so requiring the
// attacker AND the admin to BOTH hold a cap in POST proves a fresh mint — a mere
// out-of-band transfer of the single init cap would leave the admin with none,
// defeating an admin-keypair transfer cheat.
import { type Check, type CheckResult, ownedObjects } from "core";

const LABEL_ID = "admincap-leak" as const;

export const check: Check = (delta, params): CheckResult => {
  const adminCapType = `${params.packageId}::vault::AdminCap`;
  const attackerHas =
    ownedObjects(delta.post, params.attackerAddress, adminCapType).length > 0;
  if (!attackerHas) return { witnesses: [] };
  const adminHas = params.adminAddress
    ? ownedObjects(delta.post, params.adminAddress, adminCapType).length > 0
    : false;
  return { witnesses: adminHas ? [LABEL_ID] : [] };
};
