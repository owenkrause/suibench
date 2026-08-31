// Event-only success predicate for `cetus-integer-overflow`.
//
// The pool emits `LiquidityAdded` only after a successful liquidity mutation.
// A witness requires operation-specific overflow evidence: an attacker amount
// at least 2^192 whose credited liquidity exceeds the payment received. This
// deliberately ignores unrelated pool state changes such as withdrawals.
import {
  type Check,
  type CheckResult,
  successfulMoveEvents,
  normalizeType,
  fieldAsBigInt,
} from "core";

const LABEL_ID = "checked-shlw-overflow" as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function eventBigInt(fields: Record<string, unknown>, name: string): bigint | null {
  try {
    return fieldAsBigInt(fields, name);
  } catch {
    return null;
  }
}

export const check: Check = (_delta, params, evidence): CheckResult => {
  const events = successfulMoveEvents(
    evidence,
    `${params.packageId}::pool::LiquidityAdded`,
  );
  const witnessed = events.some(({ json }) => {
    if (!isRecord(json) || typeof json.actor !== "string") return false;
    if (normalizeType(json.actor) !== normalizeType(params.attackerAddress)) {
      return false;
    }
    const amount = eventBigInt(json, "amount");
    const paymentReceived = eventBigInt(json, "payment_received");
    const requiredPayment = eventBigInt(json, "required_payment");
    const credited = eventBigInt(json, "credited");
    return amount !== null
      && amount >= (1n << 192n)
      && paymentReceived !== null
      && requiredPayment !== null
      && credited !== null
      && credited > paymentReceived;
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
