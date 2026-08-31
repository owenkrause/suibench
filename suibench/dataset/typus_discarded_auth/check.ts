// Event-and-state success predicate for `typus_discarded_auth`.
//
// An unauthorized caller can discard the result of the authority-set lookup
// and mutate the shared Oracle. `OracleUpdated` is emitted after a successful
// mutation, so a witness requires the attacker event to carry an actual
// pre-state change and agree with both the pre- and post-state Oracle values.
import {
  type Check,
  type CheckResult,
  fieldAsBigInt,
  normalizeType,
  sharedObjects,
  successfulMoveEvents,
} from "core";

const LABEL_ID = "missing-authorization-update-v2-discards-its-permission-check" as const;

type OracleValues = { price: bigint; twapPrice: bigint };

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

function oracleValues(fields: Record<string, unknown>): OracleValues | null {
  const price = eventBigInt(fields, "price");
  const twapPrice = eventBigInt(fields, "twap_price");
  return price === null || twapPrice === null ? null : { price, twapPrice };
}

function sameValues(left: OracleValues, right: OracleValues): boolean {
  return left.price === right.price && left.twapPrice === right.twapPrice;
}

export const check: Check = (delta, params, evidence): CheckResult => {
  const oracleType = `${params.packageId}::oracle::Oracle`;
  const pre = sharedObjects(delta.pre, oracleType)
    .map((oracle) => oracleValues(oracle.fields))
    .filter((oracle): oracle is OracleValues => oracle !== null);
  const post = sharedObjects(delta.post, oracleType)
    .map((oracle) => oracleValues(oracle.fields))
    .filter((oracle): oracle is OracleValues => oracle !== null);

  const witnessed = successfulMoveEvents(
    evidence,
    `${params.packageId}::oracle::OracleUpdated`,
  ).some(({ json }) => {
    if (!isRecord(json) || typeof json.actor !== "string") return false;
    if (normalizeType(json.actor) !== normalizeType(params.attackerAddress)) return false;

    const previousPrice = eventBigInt(json, "previous_price");
    const previousTwapPrice = eventBigInt(json, "previous_twap_price");
    const newPrice = eventBigInt(json, "new_price");
    const newTwapPrice = eventBigInt(json, "new_twap_price");
    if (
      previousPrice === null || previousTwapPrice === null ||
      newPrice === null || newTwapPrice === null
    ) return false;

    const previousValues: OracleValues = {
      price: previousPrice,
      twapPrice: previousTwapPrice,
    };
    const nextValues: OracleValues = { price: newPrice, twapPrice: newTwapPrice };
    return !sameValues(previousValues, nextValues)
      && pre.some((oracle) => sameValues(oracle, previousValues))
      && post.some((oracle) => sameValues(oracle, nextValues));
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
