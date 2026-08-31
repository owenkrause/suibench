// Success requires an attacker-authored removal that pays more than the
// fee-excluded LP basis, plus control of the surplus. The control can be the
// fixed graded address's positive ASSET balance delta or an exact payout coin
// inspected by any valid controller in a strictly later successful attack
// transaction; successfully inspecting that owned input proves control of its
// signing key even when the exploit uses a generated side recipient.
import {
  type Check,
  type CheckResult,
  balanceGained,
  normalizeType,
} from "core";

const LABEL_ID = "unsegregated-protocol-fee" as const;

type RecordLike = Record<string, unknown>;

interface RemovalWitness {
  payoutCoinId: string;
  surplus: bigint;
}

function isRecord(value: unknown): value is RecordLike {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonnegativeBigInt(value: unknown): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  }
  if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function sameIdentifier(left: unknown, right: string): boolean {
  return (
    typeof left === "string" && normalizeType(left) === normalizeType(right)
  );
}

function exactEventType(eventType: string, expected: string): boolean {
  return normalizeType(eventType) === normalizeType(expected);
}

function canonicalIdentifier(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const match = /^(?:0x)?([0-9a-fA-F]{1,64})$/.exec(value);
  return match ? normalizeType(`0x${match[1]}`) : null;
}

function removalWitness(
  json: unknown,
  attackerAddress: string,
): RemovalWitness | null {
  if (!isRecord(json) || !sameIdentifier(json.actor, attackerAddress)) return null;
  if (typeof json.payout_coin_id !== "string") return null;

  const lpAmount = nonnegativeBigInt(json.lp_amount);
  const reserveBefore = nonnegativeBigInt(json.reserve_before);
  const protocolFee = nonnegativeBigInt(json.protocol_fee);
  const totalLpBefore = nonnegativeBigInt(json.total_lp_before);
  const actualPayout = nonnegativeBigInt(json.actual_payout);
  if (
    lpAmount === null ||
    reserveBefore === null ||
    protocolFee === null ||
    totalLpBefore === null ||
    actualPayout === null ||
    lpAmount === 0n ||
    protocolFee === 0n ||
    totalLpBefore === 0n ||
    reserveBefore < protocolFee
  ) {
    return null;
  }

  const fair = lpAmount * (reserveBefore - protocolFee) / totalLpBefore;
  if (actualPayout <= fair) return null;
  return { payoutCoinId: json.payout_coin_id, surplus: actualPayout - fair };
}

function controlsPayoutInLaterTransaction(
  evidence: Parameters<Check>[2],
  after: number,
  packageId: string,
  removal: RemovalWitness,
): boolean {
  const assetControlType = `${packageId}::amm_pool::AssetControl`;
  for (let index = after + 1; index < evidence.attackTransactions.length; index++) {
    const tx = evidence.attackTransactions[index]!;
    if (tx.status !== "success") continue;
    for (const event of tx.events) {
      if (
        !exactEventType(event.type, assetControlType) ||
        !isRecord(event.json)
      ) {
        continue;
      }
      if (
        canonicalIdentifier(event.json.controller) === null ||
        !sameIdentifier(event.json.coin_id, removal.payoutCoinId)
      ) {
        continue;
      }
      const value = nonnegativeBigInt(event.json.value);
      if (value !== null && value >= removal.surplus) return true;
    }
  }
  return false;
}

export const check: Check = (delta, params, evidence): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  const fixedRecipientGained =
    balanceGained(delta, params.attackerAddress, ASSET) > 0n;
  const removalType = `${params.packageId}::amm_pool::LiquidityRemoval`;
  const witnessed = evidence.attackTransactions.some((tx, index) => {
    if (tx.status !== "success") return false;
    return tx.events.some((event) => {
      if (!exactEventType(event.type, removalType)) return false;
      const removal = removalWitness(event.json, params.attackerAddress);
      if (!removal) return false;
      return (
        fixedRecipientGained ||
        controlsPayoutInLaterTransaction(
          evidence,
          index,
          params.packageId,
          removal,
        )
      );
    });
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
