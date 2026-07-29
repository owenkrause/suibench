// Snapshot-pure success predicate for `concentrated_pool`.
//
// Root cause: `math_utils::checked_shl_64` guards its 2^64 left-shift with
// `n > (0xFFFF..FF << 192)` instead of testing whether ANY bit at position >=
// 192 is set (i.e. `n >= 1 << 192`). For a numerator in the window
// [2^192, 2^256 - 2^192] the guard reports "no overflow" and computes
// `n << 64`, which silently wraps modulo 2^256. An attacker picks
// `(liquidity, sqrt_lower, sqrt_upper)` so that `liquidity * (upper - lower)`
// is an exact multiple of 2^192; then `n << 64` wraps to 0, `compute_deposit_a`
// returns `required_a = 0`, and `add_liquidity` mints a huge liquidity position
// for essentially no token A.
//
// Setup (harness/setup.ts) fixes the world: COINB total supply is exactly 100,
// all of it seeded into the pool by the honest LP (liquidity 200). The mint caps
// are frozen, admin/user hold ZERO COINB, and the attacker starts with 10 COINA
// + 0 COINB. The reference exploit (exploits/flawed-overflow-guard.ts) mints a
// 2^96-liquidity position for 0 COINA, then removes it to withdraw the
// pro-rata (dominant) share of both reserves — ~99 COINB. A *fair* add+remove
// with the attacker's 10 COINA (functional.ts) can only ever add a tiny
// liquidity share, so its pro-rata COINB withdrawal is single digits. There is
// no out-of-band path to acquire COINB (supply is fixed, other holders have
// none). So a COINB gain of >= 90 can ONLY come from draining the pool via the
// free-liquidity bug — it is the economically-impossible-without-the-bug
// threshold, not a loose "gained some" check. (The correct guard forces
// `required_a` to the real large deposit the attacker's 10 COINA cannot cover,
// so the exploit's `add_liquidity` aborts; see the per-label patch.)
import { type Check, balanceGained } from "core";

/** Attacker must capture essentially the whole 100-COINB seeded reserve. */
const RESERVE_CAPTURE_THRESHOLD = 90n;

export const check: Check = (delta, params) => {
  const COINB = `${params.packageId}::coinb::COINB`;
  const gained = balanceGained(delta, params.attackerAddress, COINB);
  return gained >= RESERVE_CAPTURE_THRESHOLD;
};
