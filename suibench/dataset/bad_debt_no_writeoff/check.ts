// Event-only multi-label check for the two labeled bugs in this pool. Each
// label is decided by its own operation's Move event, independently of the
// other — an attacker's aggregate ASSET gain cannot manufacture a witness for
// a mechanism it did not commit:
//
//   (A) bad-debt-no-writeoff — a successful `redeem` emitted a `Redemption`
//       event for the attacker where `actual_payout` exceeds the
//       `fair_written_off_payout` computed and emitted atomically with it.
//   (B) collateral-release-no-repay — a successful `withdraw_collateral`
//       emitted a `CollateralRelease` event for the attacker with
//       `debt_remaining > 0` (collateral released while still owing).
import {
  type Check,
  type CheckResult,
  successfulMoveEvents,
  normalizeType,
  fieldAsBigInt,
} from "core";

const A = "bad-debt-no-writeoff" as const;
const B = "collateral-release-no-repay" as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function eventBigInt(
  fields: Record<string, unknown>,
  name: string,
): bigint | null {
  try {
    return fieldAsBigInt(fields, name);
  } catch {
    return null;
  }
}

function isAttacker(
  fields: Record<string, unknown>,
  attackerAddress: string,
): boolean {
  return typeof fields.actor === "string"
    && normalizeType(fields.actor) === normalizeType(attackerAddress);
}

export const check: Check = (_delta, params, evidence): CheckResult => {
  const redemptions = successfulMoveEvents(
    evidence,
    `${params.packageId}::lending_pool::Redemption`,
  );
  const releases = successfulMoveEvents(
    evidence,
    `${params.packageId}::lending_pool::CollateralRelease`,
  );
  const sawA = redemptions.some(({ json }) => {
    if (!isRecord(json) || !isAttacker(json, params.attackerAddress)) return false;
    const burned = eventBigInt(json, "ctokens_burned");
    const actual = eventBigInt(json, "actual_payout");
    const fair = eventBigInt(json, "fair_written_off_payout");
    return burned !== null && actual !== null && fair !== null
      && burned > 0n && actual > fair;
  });
  const sawB = releases.some(({ json }) => {
    if (!isRecord(json) || !isAttacker(json, params.attackerAddress)) return false;
    const debt = eventBigInt(json, "debt_remaining");
    const collateral = eventBigInt(json, "collateral_released");
    return debt !== null && collateral !== null && debt > 0n && collateral > 0n;
  });
  return { witnesses: [...(sawA ? [A] : []), ...(sawB ? [B] : [])] };
};
