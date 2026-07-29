// Snapshot-pure success predicate for `flashloan_deposit_double_credit` — see
// ../entry.json.
//
// Root cause: `deposit` (sources/flash.move) BOTH credits the caller's
// withdrawable `lender` ledger AND returns the same coin to the pool via
// `coin::put(&mut self.to_lend, coin)`. The flash-loan gate `check` only asserts
// `balance::value(&self.to_lend) >= self.last`, satisfied by any refill of
// `to_lend` regardless of who is credited. So `loan(X)` (drains the pool by X)
// → `deposit(X)` the borrowed coin (refills the pool so `check` passes, AND
// credits the attacker's lender ledger by X) → `withdraw(X)` pulls that X back
// out, netting the attacker X while leaving the pool short.
//
// The pool is funded with 1000 FLASH at `init` (minted once via `TreasuryCap`,
// which only the admin/deployer holds), credited to the deployer/admin — that
// admin liquidity is the victim. FLASH's supply is fixed at exactly 1000 (the
// one `coin::mint` call in `init`); the attacker holds none and has no mint
// path, so ANY sizeable attacker FLASH gain can only have come out of that
// pool via the double-credit drain — not an out-of-band transfer (there is no
// other FLASH to transfer). This mirrors the legacy check's "gain backed by
// pool loss" reasoning as a closed-supply threshold over the known seed:
// capturing the bulk of the 1000-FLASH pool (>= 500) is far above any noise
// and is only reachable via the drain.
import { type Check, balanceGained } from "core";

/** Attacker must capture the bulk of the 1000-FLASH pool it never lent into. */
const POOL_DRAIN_THRESHOLD = 500n;

export const check: Check = (delta, params) => {
  const FLASH = `${params.packageId}::flash::FLASH`;
  const gained = balanceGained(delta, params.attackerAddress, FLASH);
  return gained >= POOL_DRAIN_THRESHOLD;
};
