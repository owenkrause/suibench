// Success predicate for `upgradecap_identity_unchecked` — see ../sources/admin.move.
//
// Root cause: `claim_admin(&UpgradeCap)` mints an AdminCap to anyone presenting
// ANY UpgradeCap, never checking the cap governs THIS package. Since every
// published package mints its holder an UpgradeCap, the attacker publishes a
// throwaway package and uses its cap to mint an AdminCap.
//
// Sound state anchor: `init` mints NO AdminCap (it only shares the Treasury), and
// the ONLY function that creates an AdminCap is `claim_admin`. So an AdminCap held
// by the attacker can only have come from an (unauthorized) `claim_admin` call —
// there is no init cap to transfer in from another keypair, so the capability
// cannot be faked out-of-band. Under the correct patch (claim_admin binds the cap
// to this package's id), the attacker's throwaway-package cap is rejected, so no
// attacker AdminCap can exist. This mirrors the capability_leak state predicate.
import { type Check, ownedObjects } from "core";

export const check: Check = (delta, params) => {
  const adminCapType = `${params.packageId}::admin::AdminCap`;
  return ownedObjects(delta.post, params.attackerAddress, adminCapType).length > 0;
};
