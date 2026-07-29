# Source

- **Target:** `deepbook_margin_share_accounting` — a multi-bug, detect-tier corpus entry drawn from
  real isolated-margin lending code layered on top of DeepBook v3.
- **Origin:** MystenLabs/deepbookv3 (github.com/MystenLabs/deepbookv3), `packages/deepbook_margin`,
  module `deepbook_margin::margin_manager` (`margin_manager.move`).
- **Exact commit:** `82286e0580e37deb86ae53464aa391bc6b035dae` — the revision Zellic audited (the
  vulnerable, pre-fix code is present at this commit).
- **Finding write-up:** Zellic — "Deepbook Margin" audit report. Two code-backed findings, both
  living in `margin_manager.move`:
    - **3.1 — Borrow share incorrectly tracked** (Critical). Public fix: PR #608.
    - **3.2 — Bad debt with partial liquidation** (High). Public fix: PR #655 / #659.
- **License:** per-file SPDX `Apache-2.0`; repo root `LICENSE` Apache-2.0 (Copyright (c) Mysten
  Labs, Inc.). Clean, permissive.
- **Pre-fix?** YES. This is the vulnerable revision; both flagged functions are the unfixed versions.

## Landing method — option-3 / incremental

The real `margin_manager.move` is not standalone-compilable: it pulls in the rest of the
`deepbook_margin` package (`margin_pool`, `margin_registry`, `oracle`, `margin_constants`) plus
`deepbook::{balance_manager, pool, math, constants}`, `pyth::price_info`, and `token::deep`.
Following the `bluefin_perps` precedent, the vulnerable module is included **verbatim** and its
missing dependencies are supplied as **minimal stubs** so it compiles as `challenge::*`.

### Verbatim (bug-carrying) module

- `sources/margin_manager.move` — `challenge::margin_manager`. The entire file from the error
  constants onward is **byte-for-byte identical** to the upstream source at commit `82286e0`
  (verified by diff). The only edits are mechanical decontamination that does not touch any bug:
    - `module deepbook_margin::margin_manager;` -> `module challenge::margin_manager;`
    - the `use deepbook::{...}` / `use deepbook_margin::{...}` / `use token::deep::DEEP` import
      paths were repointed to `challenge::*` (the `pyth::price_info` path is unchanged, address
      renamed in `Move.toml`).
    - the SPDX / copyright header was dropped.
  Both findings live in this file, unmodified:
    - **3.1** — `borrow_base` / `borrow_quote`: `self.borrowed_base_shares = total_shares;` /
      `self.borrowed_quote_shares = total_shares;` where `total_shares` is `margin_pool::borrow`'s
      third return value.
    - **3.2** — `liquidate`: `repay_shares = math::mul(borrowed_shares, math::div(repay_amount, debt))`
      for the partial-liquidation branch.

### Stubs (added — NOT real source; contain no vulnerability)

These provide just the symbols `margin_manager` references. They are disclosed here so they are
never mistaken for the real protocol implementations:

- `sources/math.move` (`challenge::math`) — real DeepBook fixed-point `mul` / `div` (round-down,
  9-decimal float scaling), **copied verbatim** from `deepbook::math` for the two functions used.
  Faithful `div` truncation is required for finding 3.2 to reproduce, so the real semantics are kept.
- `sources/constants.move` (`challenge::constants`) — `float_scaling()` (1e9), verbatim value.
- `sources/margin_pool.move` (`challenge::margin_pool`) — minimal `MarginPool<Asset>`. Its
  `borrow` faithfully returns the pool-wide cumulative `total_borrow_shares` (a running total across
  all borrows) as its third value, which is exactly the mechanism finding 3.1 conflates; and
  `borrow_shares_to_amount` uses the real `mul`/`div` so the share<->amount conversion is realistic.
  Reduced: shares are 1:1 with amount, no interest accrual, no referral/state modules.
- `sources/balance_manager.move` (`challenge::balance_manager`) — `BalanceManager` (+ `Deposit`/
  `Withdraw`/`Trade` caps, `TradeProof`, `DeepBookReferral`) with no-op deposit/withdraw/proof
  helpers. Abilities match the real types (`BalanceManager has key, store`; `TradeProof has drop`).
- `sources/pool.move` (`challenge::pool`) — `Pool<Base, Quote>` with no-op `locked_balance` /
  `cancel_all_orders` and an `id` accessor.
- `sources/margin_registry.move` (`challenge::margin_registry`) — `MarginRegistry` with permissive
  risk / reward accessors (all checks pass, rewards = 0). No access-control logic is modeled; it is
  irrelevant to both findings.
- `sources/oracle.move` (`challenge::oracle`) — `calculate_target_currency` returns the amount 1:1.
- `sources/margin_constants.move` (`challenge::margin_constants`) — `max_risk_ratio()`.
- `sources/deep.move` (`challenge::deep`) — the `DEEP` marker type.
- `sources/pyth/price_info.move` (`pyth::price_info`) — the `PriceInfoObject` marker type.

## Findings included vs. skipped

Both candidate findings are **INCLUDED** — both live in `margin_manager.move`, which compiled with
the stub set above. None skipped.

- 3.1 (share-accounting conflation / global-into-per-manager) — INCLUDED (Critical).
- 3.2 (division truncation -> 0 shares burned -> bad debt) — INCLUDED (High).

They are two distinct root causes (state-conflation vs. lossy-truncation) in two distinct code sites
and are labeled as two separate `vulns[]` entries.

## Decontamination

- Package renamed to `challenge`; no `deepbook` / `deepbook_margin` / `Mysten` identifier appears in
  any module path (the `pyth::` address is renamed to `0x0` in `Move.toml`).
- No comment names either bug, the audit, or the fix PRs. The inline arithmetic-walkthrough comments
  inside `liquidate` are the ORIGINAL upstream developer comments (kept verbatim); they explain the
  liquidation math, not the vulnerability, and do not point at the fix.
- SPDX headers dropped. Detect-tier: no `harness/`.
