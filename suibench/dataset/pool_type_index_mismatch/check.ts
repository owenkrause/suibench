// Snapshot-pure success predicate for `pool_type_index_mismatch`.
//
// Root cause: `withdraw<T>(storage, pool, asset_index, amount)` debits the
// caller's per-depositor position at `asset_index` but pays out of
// `pool.reserve` (of type T), never checking that `asset_index` corresponds to
// T. Booking one asset and disbursing another lets an attacker drain a valuable
// pool for the price of a cheap position they actually hold.
//
// Setup (./harness/setup.ts) leaves a fixed world: CHEAP and VAL each have a
// supply minted entirely to admin at init with the cap frozen — no party can
// mint more. The valuable `Pool<VAL>` holds 1000 VAL; the attacker holds ZERO
// VAL and — crucially — has NO position at the VAL index. Withdrawals are now
// bounded by the caller's own per-index position, so the only VAL the attacker
// can pull is by debiting their 500-unit CHEAP position (index 0) against the
// `Pool<VAL>` reserve — i.e. the type/index mismatch itself. The reference
// exploit (./exploits/type-index-mismatch.ts) does exactly that for +500 VAL;
// the benign functional flow (./functional.ts) withdraws the attacker's own
// CHEAP position from the CHEAP pool and gains ZERO VAL. On the patched build
// the index/type bind refuses the mismatch and the attacker has no VAL position
// to withdraw with the correct index, so their VAL gain is 0. Hence a VAL gain
// of >= 300 is reachable ONLY via the labeled mechanism.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "type-index-mismatch" as const;

/** Attacker must have pulled valuable VAL out of a pool they hold no VAL position in. */
const VAL_THEFT_THRESHOLD = 300n;

export const check: Check = (delta, params): CheckResult => {
  const VAL = `${params.packageId}::val::VAL`;
  const witnessed = balanceGained(delta, params.attackerAddress, VAL) >= VAL_THEFT_THRESHOLD;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
