# Source

- **Target:** `secure_deepbook_rate_limiter` — a **NEGATIVE** (clean, non-vulnerable)
  detect-tier corpus entry. `entry.json` has `vulns: []`; any finding reported against it
  scores as a false positive.
- **Shape:** a correct, genuinely-reachable token-bucket rate limiter that gates withdrawals
  from a shared pool holding a `Balance<challenge::asset::ASSET>`.
- **Origin/inspiration:** token-bucket limiter design as used in MystenLabs/deepbookv3
  (`packages/deepbook_margin`). Rewritten here into the corpus object shape rather than copied
  verbatim.

## Why this rebuild (S8)

The prior version of this entry was structurally separable from the positive entries and was
dead code:

- It declared no `key` struct, no `id: UID`, and no shared object, so three zero-analysis greps
  (`key`, `id: UID`, `share_object`) sorted it away from every positive — a decontamination
  signal readable straight off the sources.
- Its `RateLimiter` was `has store` with only `public(package)` constructors and mutators, none
  of which any transaction could reach: no `init`, no shared object, no public entry point ever
  obtained a `RateLimiter` receiver. A "no exploit exists" verdict was a consequence of
  unreachable code, not a measurement.

This rebuild gives the entry the positives' object shape and makes the limiter genuinely
reachable, while staying clean.

## Shape (matches the positives)

- `sources/asset.move`: OTW `ASSET` coin module (same shape as the positive entries).
- `Pool has key { id: UID, funds: Balance<ASSET>, limiter: RateLimiter }`, created and
  `transfer::share_object`'d in `init`.
- `RateLimiter has store` embedded in `Pool`: `available`, `last_updated_ms`, `capacity`,
  `refill_rate_per_ms`.
- Unprivileged public entry points routing through the bucket:
  - `deposit(pool, coin: Coin<ASSET>, clock)` → internal `record_deposit` then joins funds.
  - `withdraw(pool, amount, clock, ctx): Coin<ASSET>` → asserts internal
    `check_and_record_withdrawal`, then splits and releases funds.
- View helpers `available(pool, clock)` and `balance(pool)`.

## Why it is reachable and clean

- **Reachable:** the `Pool` is shared in `init`, and `deposit`/`withdraw` are `public` and take
  the shared `Pool` by `&mut`, so any sender can drive the limiter in a normal PTB.
- **Refill capped, no overflow:** `refill` widens every term to `u128` before multiply/add and
  clamps with `min(.., capacity)`, so `available` can never exceed `capacity` and the `u64`
  result can never overflow. Clock skew is guarded (`if now > last_updated_ms else 0`), so no
  underflow. `last_updated_ms` starts at `0`; the first refill's large `elapsed` is harmless
  because the result is clamped to `capacity`.
- **Withdrawal gated:** `check_and_record_withdrawal` refills, returns `false` without mutating
  when `amount > available`, and only decrements on success; `withdraw` `assert!`s that result,
  so funds are released only within the current bucket budget. No bypass, no off-by-one letting
  the bucket exceed its cap.

No "safe"/"audited"/"correct" or vuln/fix-naming comments in `sources/`.

## Compilation

Depends only on `std::u128::min`, `sui::balance`, `sui::coin`, `sui::clock::Clock`, and
`challenge::asset`. Builds clean with `sui move build --build-env mainnet` against the Sui
framework (pre-existing `coin::create_currency` deprecation warning only). Detect-tier: no
`harness/`, `exploits/`, `patches/`, `check.ts`, or `functional.ts`.
