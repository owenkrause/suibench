# Source

- **Author / origin:** MoveCTF (1st official MoveCTF challenge set) — "FlashLoan".
- **Source URL:** https://github.com/movectf/MoveCTF-1st-Challenge (FlashLoan/sources/module.move)
- **Report / name:** MoveCTF 1st Challenge — FlashLoan.
- **Date:** challenge from 2022; adapted for this corpus 2026-07-08.
- **License:** No LICENSE file in the MoveCTF-1st-Challenge repo and no SPDX header on the
  original file — license **UNSPECIFIED**. Flagged.
- **Vuln class:** Flash-loan accounting — a `deposit` that double-credits the lender
  ledger lets the pool be drained.
- **One-line description:** `deposit` credits the caller's withdrawable `lender` ledger AND
  returns the same coin to the pool's `to_lend`; because the flash-loan repayment gate
  `check` only requires `to_lend >= last`, an attacker can `loan(X)` -> `deposit(X)` (which
  refills `to_lend` so `check` passes while also crediting their ledger by X) -> `withdraw(X)`,
  netting X per cycle and draining the pool.

## Verbatim vs. re-authored

**Verbatim vuln logic.** `deposit`, `loan`, `repay`, `check`, `withdraw`, `create_lend`,
`balance`, and the `FLASH` / `FlashLender` / `Receipt` shapes are copied unmodified in
semantics; only syntax was modernized (see below). The double-credit in `deposit` — crediting
the `lender` ledger and calling `coin::put(&mut self.to_lend, coin)` on the same coin — and
the `to_lend >= self.last` gate in `check` are exactly as in the original. This preserves the
bug being evaluated.

## Decontamination

- **Package / module rename:** `movectf::flash` -> `challenge::flash`; package name `challenge`.
- **Removed the CTF trophy:** the original `struct Flag { user, flag }` and
  `public entry fun get_flag(...)` (which emitted a `Flag` event once `to_lend` hit zero, i.e.
  the "you solved the CTF" signal) were deleted. The realistic win is simply draining the
  pool, so no flag mechanism is needed. The now-unused `use sui::event;` was dropped with it.
- **Removed dead code:** the `struct AdminCap { id, flash_lender_id }` was defined but never
  constructed or used in the original candidate; it was removed.
- **Removed commented-out import cruft:** `// use sui::object::{Self, UID};`,
  `// use std::vector;`, and `// use std::debug;` were deleted.
- No comment in the file names or hints at the double-credit / the vulnerability under test.

## Modernization (2022 Move -> Sui 1.69 / edition 2024)

Mechanical syntax updates only — no accounting or flash-loan logic changed:

- `struct X` -> `public struct X` for every kept struct (`FLASH`, `FlashLender`, `Receipt`).
- **`coin::create_currency` signature change:** the 2022 form
  `let cap = coin::create_currency(witness, 2, ctx);` no longer compiles. The current
  signature returns `(TreasuryCap<FLASH>, CoinMetadata<FLASH>)` and takes name/symbol/
  description/icon args, so it is now
  `let (mut treasury, metadata) = coin::create_currency(witness, 2, b"FLASH", b"FLASH", b"", option::none(), ctx);`.
  The metadata is disposed with `transfer::public_freeze_object(metadata)` and `treasury` is
  used everywhere the old `cap` was (`coin::mint(&mut treasury, 1000, ctx)`, then
  `transfer::public_transfer(treasury, owner)`). `coin::create_currency` is now marked
  deprecated (in favor of `coin_registry::new_currency_with_otw`); since the brief pins the
  original `create_currency` path, the deprecation warning is suppressed on `init` with
  `#[allow(deprecated_usage)]` rather than switching APIs.
- `transfer::transfer(...)` -> `transfer::public_transfer(...)` where the transferred type is
  defined in another module (`TreasuryCap`, `Coin`) — required by the 2024 object-transfer
  visibility rules.
- Added `mut` where the 2024 checker requires (`mut lender` in `create_lend`, `mut treasury`
  in `init`).
- Trimmed redundant edition-2024 auto-imports (`sui::object`, `sui::tx_context`,
  `sui::transfer`); kept the still-required `sui::balance`, `sui::coin`, `sui::vec_map`.
- Dropped the meaningless `entry` from the already-`public` `deposit` / `withdraw`
  (the current compiler lints `entry` on `public` as redundant; both remain PTB-callable, so
  this is a no-op semantically).
- `#[allow(lint(self_transfer))]` on `withdraw`: the withdrawn `Coin` is intentionally
  transferred to `tx_context::sender(ctx)` (the caller), exactly the original behavior; the
  lint is suppressed rather than restructured.

Result: `sui move build --build-env mainnet` succeeds with no errors and no warnings (one
lint explicitly suppressed as documented above).
