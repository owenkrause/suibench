// Snapshot-pure success predicate for `pool_type_index_mismatch`.
//
// Root cause: `withdraw<T>(storage, pool, asset_index, amount)` debits the
// `Storage.supply` accounting for the caller-supplied `asset_index` but pays
// out of `pool.reserve` (of type T), never checking that `asset_index`
// corresponds to T. Booking one asset and disbursing another lets an attacker
// drain a valuable pool for the price of a cheap position.
//
// Setup (./harness/setup.ts) leaves a fixed world: CHEAP and VAL each have a
// supply minted entirely to admin at init with the cap frozen — no party can
// mint more. The valuable `Pool<VAL>` holds 1000 VAL; the attacker holds ZERO
// VAL and never deposits any. The ONLY way the attacker can come to hold VAL
// is by pulling it out of the valuable pool. The reference exploit
// (./exploits/type-index-mismatch.ts) books against the CHEAP index (0) while
// disbursing 500 VAL from `Pool<VAL>`, so the attacker ends +500 VAL. The
// benign functional flow (./functional.ts) withdraws the attacker's own CHEAP
// position from the CHEAP pool and gains ZERO VAL. So a VAL gain of >= 300 can
// ONLY come from the type/index-mismatch theft — it is not a loose "gained
// some" check but a gain that is impossible without the bug.
import { type Check, balanceGained } from "core";

/** Attacker must have pulled valuable VAL out of a pool they hold no VAL position in. */
const VAL_THEFT_THRESHOLD = 300n;

export const check: Check = (delta, params) => {
  const VAL = `${params.packageId}::val::VAL`;
  return balanceGained(delta, params.attackerAddress, VAL) >= VAL_THEFT_THRESHOLD;
};
