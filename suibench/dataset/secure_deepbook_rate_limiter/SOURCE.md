# Source

- **Target:** `secure_deepbook_rate_limiter` — a **NEGATIVE** (clean, non-vulnerable)
  detect-tier corpus entry: a correct, stateful token-bucket rate limiter used to bound
  withdrawal rates on a margin/lending pool. `groundtruth.json` has `vulns: []`.
- **Origin:** MystenLabs/deepbookv3 (github.com/MystenLabs/deepbookv3), `packages/deepbook_margin`,
  module `deepbook_margin::rate_limiter` (`rate_limiter.move`). Production code from a
  heavily-audited protocol; the module's own doc-comment cites a token-bucket design reference.
- **License:** per-file SPDX `Apache-2.0`; repo root `LICENSE` Apache-2.0 (Copyright (c) Mysten
  Labs, Inc.). Clean, permissive.
- **Pre-fix?** N/A — this is not a vulnerable revision. It is a correct module included as a
  realistic negative.

## Why this is a realistic negative (plausibly-flaggable but clean)

An auditor or model is tempted to flag four things; all are correctly handled:

1. The `elapsed` time subtraction (`current_time - self.last_updated_ms`) as a possible
   underflow on clock skew — but it is guarded by `if (current_time > self.last_updated_ms)`
   (else `0`), so no underflow.
2. The refill accumulation `available + elapsed * refill_rate_per_ms` as an overflow — but every
   term is widened to `u128` before the mul/add and then clamped with `min(.., capacity)`, so it
   cannot overflow the `u64` result.
3. `check_and_record_withdrawal` as a possible over-withdraw — but it returns `false` (and does
   not mutate `available`) when `amount > available`, and only decrements on success.
4. `update_config` changing capacity/rate mid-flight — but it calls `refill(clock)` FIRST to
   settle accrual under the old rate, then clamps `available` down to the new `capacity`.

The token-bucket algorithm is textbook and each arithmetic step is explicitly guarded
(u128 widening + min-clamp + skew guard). Confidence it is genuinely clean: HIGH.

## Decontamination

- Package renamed `deepbook_margin` -> `challenge`; module is now `challenge::rate_limiter`.
- Dropped the SPDX / copyright header.
- Removed the doc-comment "Reference: <chainlink RateLimiter.sol URL>" line (the only
  DeepBook/Mysten/external identifier); replaced the doc comment with a neutral one-liner.
- No "safe" / "audited" / "correct" comment that would tell a model the module is clean.
- Body otherwise **verbatim**: all function bodies (including the `#[test_only]` accessors) are
  byte-for-byte the upstream source; only the package address and the two comment lines changed.

## Compilation

Depends only on `std::u128::min`, `std::u64::max_value!`, and `sui::clock::Clock`. Builds clean
with `sui move build --build-env mainnet` against the Sui framework; no external protocol types or
stubs required. Detect-tier: no `harness/`.
