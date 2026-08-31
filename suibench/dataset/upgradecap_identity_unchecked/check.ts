// Success predicate for `upgradecap_identity_unchecked` — see ../sources/admin.move.
//
// Root cause: `claim_admin(&UpgradeCap)` mints an AdminCap to anyone presenting
// ANY UpgradeCap, never checking the cap governs THIS package. Since every
// published package mints its holder an UpgradeCap, the attacker publishes a
// throwaway package and uses its cap to mint an AdminCap.
//
// `claim_admin` emits `AdminClaim` after it constructs an AdminCap. The event
// binds the successful mint to both the caller and the package governed by the
// presented UpgradeCap, so the final AdminCap recipient cannot hide the attack.
// Under the patch, a foreign UpgradeCap aborts before construction and emission.
import {
  type Check,
  type CheckResult,
  normalizeType,
  successfulMoveEvents,
} from "core";

const LABEL_ID = "upgradecap-identity-unchecked" as const;

function asId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const match = /^(?:0x)?([0-9a-fA-F]{1,64})$/.exec(value);
  return match ? normalizeType(`0x${match[1]}`) : null;
}

export const check: Check = (_delta, params, evidence): CheckResult => {
  const attacker = asId(params.attackerAddress);
  const expectedPackage = asId(params.packageId);
  if (!attacker || !expectedPackage) return { witnesses: [] };

  const witnessed = successfulMoveEvents(
    evidence,
    `${params.packageId}::admin::AdminClaim`,
  ).some(({ json }) => {
    if (json === null || typeof json !== "object" || Array.isArray(json)) return false;
    const fields = json as Record<string, unknown>;
    const actor = asId(fields.actor);
    const capPackage = asId(fields.cap_package);
    const adminCapId = asId(fields.admin_cap_id);
    return actor === attacker && capPackage !== null && adminCapId !== null
      && capPackage !== expectedPackage;
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
