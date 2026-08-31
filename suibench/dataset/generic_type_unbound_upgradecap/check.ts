// Snapshot-pure success predicate for `generic_type_unbound_upgradecap` — see
// ./sources/mtoken.move and ./entry.json.
//
// Root cause: `revoke_transfer_ownership<T>(state: &State<T>, req: ...)` gates on
// `check_owner(state)`, but the generic `State<T>` is NEVER bound to the escrowed
// `req`. `create_state<T>` is permissionless, so an attacker owns a `State<T'>`
// for a throwaway type, presents it with the VICTIM's `TransferOwnershipReq`, and
// the escrowed `UpgradeCap` is `public_transfer`'d to them.
//
// MECHANISM ANCHOR: the escrowed cap is the PROTOCOL's OWN `UpgradeCap` — the one
// minted when the challenge package is published, whose `fields.package` equals
// `params.packageId` (harness/setup.ts escrows exactly this cap). So "the attacker
// owns an UpgradeCap governing the challenge package" is reachable ONLY by stealing
// the escrow. A bare `UpgradeCap`-type match would be unsound: anyone can publish a
// throwaway package and mint a cap for free (count 0->1), satisfying it WITHOUT the
// bug and SURVIVING the gold patch — but such a decoy cap governs the attacker's OWN
// package (`fields.package !== packageId`), and the patch (bind req to its State<T>)
// aborts the steal, so both leave the attacker holding ZERO self-governing caps.
import { type Check, type CheckResult, ownedObjects, normalizeType } from "core";

const LABEL_ID = "unbound-state-authz" as const;

export const check: Check = (delta, params): CheckResult => {
  const upgradeCapType = "0x2::package::UpgradeCap";
  const wantPkg = normalizeType(params.packageId);
  const selfGovCaps = (snap: Parameters<Check>[0]["pre"]): number =>
    ownedObjects(snap, params.attackerAddress, upgradeCapType).filter(
      (c) => normalizeType(String(c.fields.package)) === wantPkg,
    ).length;
  const witnessed = selfGovCaps(delta.pre) === 0 && selfGovCaps(delta.post) > 0;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
