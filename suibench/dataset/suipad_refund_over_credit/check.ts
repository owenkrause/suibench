// Snapshot-pure success predicate for `suipad_refund_over_credit`.
//
// `vault::claim_refund` atomically records both the amount represented by the
// consumed refund ticket and the value actually paid out. The vulnerable
// arithmetic pays more than the ticket records; the patch pays exactly that
// recorded deposit. A successful attacker-authored event with a positive
// deposit and a larger payout is therefore a direct witness of the bug.
import {
  type Check,
  type CheckResult,
  fieldAsBigInt,
  normalizeType,
  successfulMoveEvents,
} from "core";

const LABEL_ID = "refund-over-credit" as const;

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

export const check: Check = (_delta, params, evidence): CheckResult => {
  const attacker = normalizeType(params.attackerAddress);
  const witnessed = successfulMoveEvents(
    evidence,
    `${params.packageId}::vault::RefundClaimed`,
  ).some(({ json }) => {
    if (!isRecord(json) || typeof json.actor !== "string") return false;
    const deposited = eventBigInt(json, "deposited_amount");
    const paid = eventBigInt(json, "paid_amount");
    return normalizeType(json.actor) === attacker
      && deposited !== null
      && paid !== null
      && deposited > 0n
      && paid > deposited;
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
