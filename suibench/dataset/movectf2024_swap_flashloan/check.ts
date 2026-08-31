// Snapshot-pure success predicate for `movectf2024_swap_flashloan` — see
// ../entry.json.
//
// Root cause: `vault::swap_a_to_b` / `swap_b_to_a` price the output off the
// INSTANTANEOUS reserve ratio (`in * reserve_out / reserve_in`) with no
// constant-product (x*y=k) invariant, no fee, and no slippage bound. Combined
// with the permissionless `flash` loan, an attacker can skew the reserves and
// then swap at the manipulated price to extract the entire pool.
//
// Setup (./harness/setup.ts) leaves a fixed world: COINB total supply is
// exactly 110 — 100 minted into the shared Vault and 10 minted to the attacker
// (the pool initializer). The mint caps are burned in `initialize`, so no more
// COINB can ever be minted, and admin/user hold ZERO COINB. The attacker
// therefore starts with 10 COINB, and the ONLY other COINB in existence is the
// pool's 100.
//
// The reference exploit (./exploits/no-constant-product.ts) flash-borrows
// COINA, swaps its 10 COINA at the skewed price for the pool's full 100 COINB,
// and repays — ending with 110 COINB (Δ +100). A *fair* single swap of the
// attacker's 10 COINA against the unskewed 100/100 pool yields only ~10 COINB
// (Δ +10), and there is no out-of-band path to acquire COINB (supply is fixed
// and the other holders have none). So a COINB gain of >= 90 can ONLY come
// from draining essentially the whole pool via the price-manipulation bug —
// it is not a loose "gained some" check but the economically-impossible-
// without-the-bug threshold.
//
// Soundness against the gold patch (measured, not assumed): the patch bars any
// swap against a pool with a flash loan outstanding, so the whole flash-then-swap
// manipulation primitive is gone — the borrow amount is irrelevant, every
// flash-based variant aborts and nets 0. (An earlier "CPMM caps the take at ~50"
// rationale was UNSOUND: a flash borrow of the entire A reserve made k=0 at swap
// time, degenerating the invariant so a tiny input still took the whole pool —
// a 91-to-100 COINB drain ON THE PATCHED BUILD.) The only gain path left on the
// patched build is a fair swap of the attacker's 10 COINA (~10 COINB), far below
// 90, so 90 cleanly separates the vulnerable build (full 100 drain) from the
// patched one.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "no-constant-product" as const;

/** Attacker must capture essentially the whole 100-COINB pool reserve. */
const POOL_CAPTURE_THRESHOLD = 90n;

export const check: Check = (delta, params): CheckResult => {
  const COINB = `${params.packageId}::coinb::COINB`;
  const gained = balanceGained(delta, params.attackerAddress, COINB);
  const witnessed = gained >= POOL_CAPTURE_THRESHOLD;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
