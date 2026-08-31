# concentrated_pool — Source provenance

Authored for this repo as an intentionally-vulnerable test contract. Layer 1
(low-level arithmetic), family: fixed-point / overflow-guard.

## Vulnerability (labeled: `flawed-overflow-guard`)
`math_utils::checked_shl_64` guards its 2^64 left-shift with
`n > (0xFFFF..FF << 192)` (= `n > 2^256 - 2^192`) instead of `n >= 1 << 192`.
For a numerator in the window `[2^192, 2^256 - 2^192]` the guard reports NO
overflow and takes the shift branch, where `n << 64` wraps modulo 2^256. The
precision fallback is the SAFE path and is never reached — the bug is that it is
NOT triggered. An attacker crafts `(liquidity, sqrt_lower, sqrt_upper)` so that
`liquidity * (upper - lower)` is a multiple of 2^192; the wrap drives the
numerator to 0, so `compute_deposit_a` returns `required_a = 0` and
`add_liquidity` mints a large-liquidity position for a zero token-A deposit. The
minted `Position` records `deposited_a = 0` for a huge `liquidity` — liquidity
with no token backing.

## Confirmability — owned-object anchor
`check.ts` reads the attacker's OWNED `Position` and fires on
`liquidity >= 2^96 && deposited_a == 0`. Only the overflow wrap can drive
`required_a` (hence `deposited_a`) to 0: every non-overflow price range rounds
`required_a` up to >= 1, and the gold patch makes the same inputs abort in
`compute_deposit_a`, so no position is minted. The predicate is therefore
unreachable on the patched build and by any legal (non-overflow) parameter set —
it is mechanism-anchored, not a balance-gain proxy.

## RE-AUTHORED — accounting artifact removed (2026-08-06)
- **RE-AUTHORED.** A minimal reconstruction of a Q64.64 overflow-guard bug.
- The first reconstruction paid withdrawals **pro-rata on raw `total_liquidity`**
  (`remove_liquidity` returned `liq/total * reserves`) and required no token B in
  `add_liquidity`. That priced liquidity from caller-chosen bounds on the way in
  but paid out on aggregate liquidity on the way out — an *unlabeled* economic
  defect: a legal narrow, high-price range (e.g. `L=2^96, lower=2^80,
  upper=2^80+1`) mints ~2^96 liquidity for `required_a = 1` WITHOUT any overflow,
  then drains the pool pro-rata. Confirmed +99 COINB on the vulnerable AND the
  gold-patched build, scoring a correct patch as a false positive (dataset review
  S1 / oracle-soundness). The labeled overflow and this artifact are the same
  economic bug via two mechanisms (both yield "tiny required_a for huge L"), so
  no snapshot predicate could distinguish them while pro-rata removal stood.
- **Fix:** `remove_liquidity` is now custodial — a `Position` records the tokens
  escrowed for it (`deposited_a`/`deposited_b`) and removal returns exactly that
  stake, so no position (overflow or otherwise) can extract more than it put in.
  With payout bound to the escrow, the labeled overflow no longer nets any coin
  value; its residual, confirmable effect is the unbacked position it mints
  (`deposited_a == 0`, `liquidity` huge), read off the owned object.
- **Patch-narrowness closed.** `compute_deposit_a` now aborts (E_INVALID_PRICE_RANGE)
  when `checked_shl_64` overflows instead of falling back to a wrong-scale value
  that returned 0 for large-denominator inputs. This keeps the gold math_utils
  patch (guard fix) sufficient: on the patched build every `overflowed` input
  aborts, so `required_a = 0`/`deposited_a = 0` is impossible.
- **Position bound to its pool.** `remove_liquidity` asserts
  `position.pool_id == object::id(pool)` (the review's cross-pool
  redemption finding); custody already caps any cross-pool payout to the
  position's own escrow.

## Decontamination
- Package/address `challenge`; modules `pool`, `math_utils`, `coina`, `coinb`. No
  vuln/audit/fix-naming comments in `sources/` (the bug is the `>` vs `>=` guard
  boundary in `checked_shl_64`). Edition `2024`. Both the vulnerable build and
  the `flawed-overflow-guard` patch build compile clean with
  `sui move build --build-env mainnet`.
