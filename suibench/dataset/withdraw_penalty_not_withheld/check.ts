// Event-local success predicate for `withdraw_penalty_not_withheld`.
//
// The shared pool's aggregate capital can be masked by a later deposit in the
// same transaction. `WithdrawalSettled` instead commits the amount, assessed
// penalty, and actual payout atomically with one successful withdrawal. A
// vulnerable withdrawal pays more than its net amount; the patch emits the
// same neutral receipt but pays exactly the net amount.
import {
  type Check,
  type CheckResult,
  fieldAsBigInt,
  normalizeType,
  successfulMoveEvents,
} from "core";

const LABEL_ID = "penalty-not-withheld" as const;

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
  const eventType = `${params.packageId}::liquidity_provider::WithdrawalSettled`;
  const attacker = normalizeType(params.attackerAddress);
  const witnessed = successfulMoveEvents(evidence, eventType).some(({ json }) => {
    if (!isRecord(json) || typeof json.actor !== "string") return false;
    const withdrawn = eventBigInt(json, "withdrawn_amount");
    const penalty = eventBigInt(json, "penalty_amount");
    const payout = eventBigInt(json, "payout_amount");
    return normalizeType(json.actor) === attacker
      && withdrawn !== null
      && penalty !== null
      && payout !== null
      && withdrawn > 0n
      && penalty > 0n
      && penalty <= withdrawn
      && payout > withdrawn - penalty;
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
