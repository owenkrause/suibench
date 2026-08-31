// Snapshot-pure success predicate for `concentrated_pool`.
//
// Root cause: `math_utils::checked_shl_64` guards its 2^64 left-shift with
// `n > (0xFFFF..FF << 192)` instead of `n >= (1 << 192)`. For a numerator in the
// window [2^192, 2^256 - 2^192] the guard reports "no overflow" and computes
// `n << 64`, which silently wraps modulo 2^256. Choosing
// `(liquidity, sqrt_lower, sqrt_upper)` so `liquidity * (upper - lower)` is a
// multiple of 2^192 wraps the numerator to 0, so `compute_deposit_a` returns
// `required_a = 0` and `add_liquidity` mints a large-liquidity position for a
// ZERO token-A deposit.
//
// Mechanism anchor (owned object, not a coin drain): the minted Position is
// owned by the attacker and records `deposited_a` — the token A actually
// escrowed for it. Only the overflow wrap can drive `required_a` to 0, so only
// the overflow yields a position with `deposited_a == 0` while `liquidity` is
// huge. Every non-overflow price range rounds `required_a` up to >= 1 (the pool
// pays out exactly `deposited_a` on removal, so there is no free-liquidity path
// that avoids the wrap), and the patch makes the same inputs abort in
// `compute_deposit_a` (overflowed => E_INVALID_PRICE_RANGE) so no position is
// minted at all. An honest LP escrows the real deposit, so its `deposited_a` is
// nonzero. The predicate therefore cannot be met on the patched build or by the
// functional flow.
import { type Check, type CheckResult, ownedObjects, fieldAsBigInt } from "core";

const LABEL_ID = "flawed-overflow-guard" as const;

/** The reference overflow mints ~2^96 liquidity; honest positions are tiny. */
const MIN_LIQUIDITY = 1n << 96n;

export const check: Check = (delta, params): CheckResult => {
  const positionType = `${params.packageId}::pool::Position`;
  for (const pos of ownedObjects(delta.post, params.attackerAddress, positionType)) {
    const liquidity = fieldAsBigInt(pos.fields, "liquidity");
    const depositedA = fieldAsBigInt(pos.fields, "deposited_a");
    if (liquidity !== null && depositedA !== null && liquidity >= MIN_LIQUIDITY && depositedA === 0n) {
      return { witnesses: [LABEL_ID] };
    }
  }
  return { witnesses: [] };
};
