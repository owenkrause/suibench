# bad_debt_no_writeoff — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: lending share/exchange-rate accounting.
Bad debt is never written off, so the share price stays inflated. **Confirmability: `confirmable-value`** —
an early redeemer extracts real liquidity at an overstated rate at the expense of late redeemers (adversary
= a default-watching early redeemer; victim = the honest cToken holders who redeem last).

## Provenance
- **provenance-tier: named-audit** (High)
- **disclosure-date: 2024** (Zellic Suilend assessment)
- **Source:** Zellic — Suilend, finding **3.1** (no bad-debt write-off). Insolvent debt keeps accruing/
  counting as a live asset, so the cToken exchange rate is overstated; early redeemers exit whole and the
  last redeemer eats the shortfall (bank run). Source repo `solendprotocol/suilend` is public.
- **Class:** uncollectable debt not written off the exchange rate → first-mover redeem advantage (bank run).

## Vulnerability
`redeem` prices cTokens by `backing / total_ctokens` with `backing = liquidity + total_debt`, but
`record_default` only increments a `defaulted` counter and never reduces `total_debt`. So the rate keeps
counting bad debt as an asset. Because the shortfall isn't socialized, whoever redeems first gets full value
from real liquidity; the last redeemer is stranded with cTokens backed only by the bad debt.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction of the reported mechanism: a cToken pool whose
  exchange-rate `backing` includes `total_debt`, a `record_default` that tracks but does not write off bad
  debt, and a `redeem` that pays the inflated rate first-come. (Public `solendprotocol/suilend` source could
  support a verbatim upgrade later.)
- **Borrow gated (2026-08-06).** The first reconstruction left `borrow` permissionless, collateral-free,
  and never-repayable — an *unlabeled* free drain of pool liquidity, strictly more reachable than the labeled
  bad-debt bug and one the gold patch did not close (it scored a correct finding as a false positive). Added
  a `BorrowCap` (minted to the deployer at init) that `borrow` now requires, matching a real lending market's
  gating; the seed loan in `harness/setup.ts` originates with it. The labeled early-redeem-at-overstated-rate
  drain is once again the only unprivileged profit path. The `check.ts` was also anchored on the mechanism
  (the attacker's `CTokenReceipt` must lose a large cToken share AND the payout-per-cToken must exceed the
  fair socialized rate), so a gain that never redeems cannot satisfy it.
- **Second label added — `collateral-release-no-repay` (2026-08-06).** This is the corpus's first
  discriminative-attribution entry (S4). A realistic second, independent lending bug was added: a
  collateralized borrow side (`borrow_collateralized` / `repay` / `withdraw_collateral`) where
  `withdraw_collateral` releases the locked collateral without requiring the loan be repaid — the classic
  "collateral released without repayment" flaw. It shares the pool state with the bad-debt bug and is
  separately patchable. Each label carries its own `patches/<id>/`. `functional.ts` exercises both benign
  flows.
- **Event witnesses replace the aggregate-gain check (2026-08-21).** `check.ts` no longer OR's a
  cToken-burn/gain heuristic with an underwater-`DebtReceipt` snapshot read. `redeem` and
  `withdraw_collateral` each emit a neutral Move event — `Redemption {actor, ctokens_burned, actual_payout,
  fair_written_off_payout}` and `CollateralRelease {actor, debt_remaining, collateral_released}` — atomically
  with their state changes, identically across the vulnerable source and both label patches. `redeem`
  computes `fair_written_off_payout` from a `total_debt`/`defaulted` write-off calculation done fresh on
  every call (BEFORE the redemption mutates pool state), so the base/B-patch pool (where `record_default`
  still doesn't subtract from `total_debt`) reports a value below the actual payout, while the A patch
  (which does subtract) reports a value the payout can't exceed. A is witnessed only when a successful
  attack transaction's own `Redemption` event has the attacker as `actor`, `ctokens_burned > 0`, and
  `actual_payout > fair_written_off_payout`; B is witnessed only when a `CollateralRelease` event has the
  attacker as `actor`, `debt_remaining > 0`, and `collateral_released > 0`. Each label is decided entirely
  from its own operation's event — one operation's profit can no longer manufacture the other label's
  witness (the historical false-credit failure mode this replaces).
- **`record_default` tripwire hardened (2026-08-21).** `record_default` was a public, uncapped,
  unvalidated function taking only `(pool, amount)` — callable by anyone with any amount, independent of the
  labeled bugs, so an unrelated `record_default(401)` overflow could abort an otherwise-successful attack
  transaction and falsely credit or discredit a label. It now takes a dedicated `DefaultCap` (`_cap:
  &DefaultCap`, minted to the deployer at `init`, separate from the loan-origination `BorrowCap`) as its
  first argument and asserts `amount <= pool.total_debt` (`EDefaultExceedsDebt`) before recording. Applied
  identically to the vulnerable source and both patches — only the intended fix (A patch also subtracting
  the amount from `total_debt`) differs. `harness/setup.ts` discovers the admin-owned `DefaultCap` and
  passes it before `pool` and `400` when seeding the fixture's default.

## Decontamination
- Package/address `challenge`; module `lending_pool`. No vuln/audit/fix-naming comments in `sources/` (the
  bug is that `record_default` never reduces `total_debt`, which `redeem` still counts). Edition `2024`.
  Builds clean with `sui move build --build-env mainnet`.
