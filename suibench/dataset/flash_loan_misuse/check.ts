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
// seeded L, so any sizeable net gain is reachable ONLY by keeping the borrowed
// liquidity (exactly the bug) — it cannot come from anywhere else. A correctly
// patched `repay` captures the loan back into the pool, so the attacker's net
// gain is 0; a legitimate flash-loan round-trip (borrow L, return it, repay)
// likewise leaves the attacker net 0 (see ./functional.ts). The threshold is
// half the seed (matching the sibling flashloan entries), giving margin for
// gas/rounding and partial drains while sitting far above the patched ceiling
// of 0 — any drain of the bulk of the pool clears it, no legitimate flow does.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "repay-any-coin" as const;

/** Half the admin-seeded pool liquidity (L = 1000); ~50%-of-seed, per siblings. */
const POOL_DRAIN_THRESHOLD = 500n;

export const check: Check = (delta, params): CheckResult => {
  const assetType = `${params.packageId}::lending_pool::LENDING_POOL`;
  const witnessed = balanceGained(delta, params.attackerAddress, assetType) >= POOL_DRAIN_THRESHOLD;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
