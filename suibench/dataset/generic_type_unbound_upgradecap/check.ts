// Success predicate for `generic_type_unbound_upgradecap` — see
// ./sources/mtoken.move and ./entry.json.
//
// Root cause: `revoke_transfer_ownership<T>(state: &State<T>, req: ...)` gates on
// `check_owner(state)`, but the generic `State<T>` is NEVER bound to the escrowed
// `req`. `create_state<T>` is permissionless, so an attacker owns a `State<T'>`
// for a throwaway type, presents it with a VICTIM's `TransferOwnershipReq`, and
// the escrowed `UpgradeCap` is `public_transfer`'d to the attacker.
//
// Soundness: the snapshot has no transaction-history/provenance reader, so we
// can't pin the seeded cap by object id the way the legacy client-backed check
// did (it queried the victim's publish tx for the exact id). Instead this relies
// on the fixed world setup.ts builds: the attacker never publishes anything in
// either the exploit (exploits/unbound-state-authz.ts) or the benign
// functional.ts flow (which only ever touches `user`), so the attacker holds
// ZERO UpgradeCaps in PRE. The ONLY way an UpgradeCap can appear in the
// attacker's owned objects in POST is the unbound-state bug transferring the
// victim's escrowed cap to them — a correct patch (bind req to its State<T>)
// makes the attacker's fake State<u64> abort, so the attacker's count stays 0.
import { type Check, ownedObjects } from "core";

export const check: Check = (delta, params) => {
  const upgradeCapType = "0x2::package::UpgradeCap";
  const attackerHadNoneBefore =
    ownedObjects(delta.pre, params.attackerAddress, upgradeCapType).length ===
    0;
  const attackerHasOneNow =
    ownedObjects(delta.post, params.attackerAddress, upgradeCapType).length >
    0;
  return attackerHadNoneBefore && attackerHasOneNow;
};
