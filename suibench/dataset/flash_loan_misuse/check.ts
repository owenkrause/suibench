// Success predicate for the `flash_loan_misuse` entry — see ../entry.json.
//
// Root cause: `repay` (sources/lending_pool.move) validates only that the
// repayment coin's value clears `borrow_amount` and then HANDS THE COIN BACK to
// the caller — it never captures the loaned funds back into the pool. So an
// attacker `borrow`s the pool's whole balance, presents any coin of sufficient
// value to clear the `repay` check (which is returned to them intact), and KEEPS
// the borrowed coin. The pool is left drained; the attacker walks away holding
// the seeded liquidity they never provided.
//
// Setup (./harness/setup.ts) leaves a fixed world: ASSET total supply is frozen
// at init, the pool is seeded with L = 1000 ASSET by the ADMIN (the attacker
// contributed none), and the attacker holds R = 1000 ASSET of their own to
// present as a repayment coin. The pre-snapshot is taken AFTER setup, so it
// already reflects the attacker's full R; the diff below is therefore the
// attacker's TRUE net ASSET profit across borrow+repay.
//
// The shared LendingPool's `balance` field is not reachable through the
// owner-keyed snapshot readers (it is a shared object, not owned by an
// address), so — as with the other pool-drain entries in this corpus
// (movectf2024_swap_flashloan, pool_type_index_mismatch) — the pool-loss/
// gain-backed-by-loss clauses collapse to a single threshold on the attacker's
// own net gain, anchored by the fixed-supply setup: ASSET's total supply is
// frozen at init and the ONLY ASSET outside the attacker's R is the pool's
// seeded L, so a >= L net gain is reachable ONLY by keeping the borrowed
// liquidity (exactly the bug) — it cannot come from anywhere else. A legitimate
// flash-loan round-trip (borrow L, return it to the pool, repay) leaves the
// attacker net 0 (see ./functional.ts), so it clears none of this threshold.
import { type Check, balanceGained } from "core";

/** The pool liquidity seeded by the admin at setup; a drain captures it all. */
const SEED_LIQUIDITY = 1000n;

export const check: Check = (delta, params) => {
  const assetType = `${params.packageId}::lending_pool::LENDING_POOL`;
  return balanceGained(delta, params.attackerAddress, assetType) >= SEED_LIQUIDITY;
};
