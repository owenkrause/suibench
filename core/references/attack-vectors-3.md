# Attack Vectors Reference — Arithmetic, Tokens & State Management (3/4)

> Part 3 of 5 · Vectors 61–90 of 143 total
> Covers: integer safety, precision loss, coin/balance operations, vector limits, dynamic fields, state lifecycle, fee logic, dust attacks

---

**61. Bitwise Operation Overflow**

- **D:** Move checks standard arithmetic overflow, but bitwise operations (`<<`, `>>`, `&`, `|`, `^`) are NOT checked. Left-shift (`<<`) can silently overflow, producing incorrect values. The Cetus $223M hack exploited a `checked_shlw` function with an incorrect shift limit (256 vs 192).
- **FP:** Custom overflow check before shift: `assert!(shift <= safe_limit)`. No bitwise operations on financial values. Shift amounts bounded by type width.

**62. Integer Overflow in Custom Math Library**

- **D:** Custom math library (fixed-point, sqrt, pow) has overflow bugs not caught by Move's default checks. The library passes unit tests but fails on edge-case inputs.
- **FP:** Library uses `u128` or `u256` intermediates for `u64` operations. Extensive fuzz testing on boundary values. Audited and well-known library used.

**63. Division Before Multiplication — Precision Loss**

- **D:** Move has no floating-point types — all math is integer. `(amount / total_supply) * price` truncates the division early, losing precision. Attacker exploits by choosing amounts that truncate to zero.
- **FP:** Multiply first: `(amount * price) / total_supply`. Higher-precision intermediate type used (u128 for u64 math). Fixed-point decimal library used.

**64. Division by Zero**

- **D:** Divisor can be zero (e.g., `total_supply`, `pool_balance`, `total_shares`). Move aborts on division by zero, causing DoS for the transaction and potentially blocking critical operations.
- **FP:** Explicit zero check: `assert!(divisor > 0, EDivisionByZero)`. Early return or special case when divisor is zero. Minimum values enforced.

**65. Integer Underflow on Subtraction**

- **D:** `a - b` where `b > a`. Move aborts on underflow in debug mode, wraps in release. Either way, the operation is incorrect — balance goes to zero (abort) or massive (wrap).
- **FP:** Explicit check: `assert!(a >= b, EUnderflow)` before subtraction. Saturating subtraction where floor of zero is correct. Checked math library used.

**66. Unsafe Type Casting**

- **D:** Casting wider to narrower type (`(value as u64)` from `u128`) without bounds check. Silently truncates, causing incorrect amounts in transfers, fees, or state updates.
- **FP:** Bounds check before cast: `assert!(value <= (U64_MAX as u128))`. Types kept consistent throughout. No narrowing casts needed.

**67. Rounding Direction Exploitation**

- **D:** Share/token calculations always round in the user's favor. Deposits round up (more shares), withdrawals round up (more tokens returned). Repeated small operations slowly drain the pool.
- **FP:** Round DOWN on deposits (fewer shares for user). Round UP on withdrawals (fewer tokens returned to user). Consistent "round against the user" policy.

**68. First Depositor Vault Inflation Attack**

- **D:** First depositor mints shares, then donates tokens directly to the vault balance (via `coin::join` or direct transfer). Share price inflates. Next depositor's deposit truncates to zero shares. First depositor redeems for everything.
- **FP:** Virtual shares/assets offset (vault starts with non-zero virtual balance). Minimum deposit enforced. Dead shares minted on init. `assert!(shares > 0)` on deposit.

**69. Round-Trip Profit**

- **D:** Due to inconsistent rounding between deposit and withdraw, `deposit(X) → withdraw(all)` returns more than X. Repeated round-trips drain the pool.
- **FP:** Rounding consistently favors the protocol in both directions. Test: `deposit(X) → withdraw(all) <= X` verified. Minimum lock period.

**70. Coin Split/Join Accounting Error**

- **D:** `coin::split` or `coin::join` used incorrectly, creating or destroying value. E.g., splitting 100 into 60 and 50 (creating 10 from nothing), or joining without adding to the tracked total.
- **FP:** Balance invariants checked after every split/join. `coin::value` verified before and after. Internal accounting matches on-chain balance.

**71. Balance vs Coin Confusion**

- **D:** `Balance<T>` (internal, no object ID) and `Coin<T>` (object with ID) used interchangeably. Converting between them without proper accounting causes lost tracking — balance exists but no coin represents it (or vice versa).
- **FP:** Clear separation: `Balance<T>` for internal state, `Coin<T>` for user-facing. `coin::into_balance` and `coin::from_balance` used with accounting. Invariant: sum of all `Balance` == sum of all `Coin`.

**72. Vector Size Limit — DoS on Unbounded Collection**

- **D:** Move vectors limited to ~1000 entries. If a vector grows beyond this limit (user registrations, positions, whitelist), insertion aborts permanently, DoS-ing the collection.
- **FP:** `sui::table_vec::TableVec` used instead of vector for unbounded data. Vector size capped with explicit check. Pagination pattern.

**73. Vector Iteration Gas Exhaustion**

- **D:** Loop iterates over entire vector on every operation. As the vector grows, gas cost increases until it exceeds the transaction gas limit, permanently blocking the operation.
- **FP:** Constant-time operations (hash table lookup). Batch processing with limit. Maximum vector size enforced. `Table` or `LinkedTable` used instead.

**74. Dynamic Field Orphaning — Value Lock**

- **D:** Parent object transferred or destroyed without removing dynamic fields. Dynamic fields become orphaned — any `Coin<T>` or valuable objects stored in them are permanently lost.
- **FP:** Cleanup function removes all dynamic fields before parent modification. `dynamic_field::exists_` checked before removal. Dynamic fields enumerated and cleaned.

**75. Fee Bypass on Alternative Code Path**

- **D:** Protocol fee applied on normal withdrawal but not on emergency withdrawal, batch operation, or admin path. Attacker routes through the fee-free path.
- **FP:** Single fee calculation function used across all paths. All exit paths charge fees. Fee-free paths have admin-only access control.

**76. Pre-Fee / Post-Fee Amount Confusion**

- **D:** Fee calculated on pre-fee amount but capacity/limit check uses post-fee amount (or vice versa). Creates accounting discrepancy — overfilling positions or under-charging fees.
- **FP:** Consistent amount used throughout (either gross or net). Fee deducted atomically. Variable naming: `amount_before_fee`, `amount_after_fee`.

**77. Fee Deduction Not Atomic**

- **D:** Fee deducted in a separate function/step from the main operation. Within a PTB, attacker skips the fee step or reorders operations to avoid fees.
- **FP:** Fee deducted within the same function as the operation. Atomic: operation fails entirely if fee fails. Hot potato enforces fee payment.

**78. Token Decimal Mismatch**

- **D:** Operations assume a specific decimal count for tokens. When a token with different decimals is used, amounts are off by orders of magnitude.
- **FP:** Coin metadata (`CoinMetadata<T>`) read for decimals. Decimal normalization applied. Only specific tokens with known decimals supported.

**79. Missing Zero-Amount Check**

- **D:** Operation accepts `amount = 0`, allowing side effects (reward snapshots, state updates, event emissions) without economic commitment.
- **FP:** `assert!(amount > 0, EZeroAmount)` on all deposit/withdraw/transfer functions. Minimum amounts enforced.

**80. Coupled State Fields Not Reset Atomically**

- **D:** Account has logically coupled fields (e.g., `shares_pending` + `total_shares`, `rewards_owed` + `last_claim_time`). On close, one is reset but not the other, leaving exploitable inconsistency.
- **FP:** All coupled fields reset in the same function call. Struct method resets all related fields atomically. Object destroyed entirely on close.

**81. Supply Invariant Violation — Mint Without Corresponding Deposit**

- **D:** Protocol mints tokens or shares without a corresponding deposit of collateral/base tokens. Total supply increases without backing, diluting all holders.
- **FP:** Mint always requires corresponding `Coin<T>` deposit. Supply invariant enforced: `total_shares * share_price == total_assets`. Mint function validates input amount.

**82. Burn Without Corresponding Withdrawal**

- **D:** Tokens burned without releasing the corresponding collateral/base tokens. The user loses tokens but receives nothing — a direct fund loss.
- **FP:** Burn always releases corresponding `Coin<T>`. Withdrawal amount calculated before burn. Atomic: burn and release in same function.

**83. Self-Transfer Inflates Accounting**

- **D:** Transfer function allows `sender == recipient`. Self-transfer triggers accounting updates (fee accrual, reward snapshots) without actual economic activity.
- **FP:** `assert!(sender != recipient)` check. Self-transfer short-circuits to no-op. Accounting unchanged on self-transfer.

**84. Missing Position Preprocessing on Transfer**

- **D:** Shares or positions transferred between users without settling pending fees/rewards on both source and destination. Destination receives unearned fees; source loses owed fees.
- **FP:** Both source and destination settled before transfer. Automatic settlement in transfer function. Fee snapshots recorded per-position.

**85. Expired Offer/Escrow Not Closeable**

- **D:** Time-limited objects (offers, escrows, locks) have no expiry-based close mechanism. Expired objects leak rent and are permanently stuck.
- **FP:** Anyone can close expired objects after deadline. `assert!(clock::timestamp_ms(&clock) >= expiry_ms)` enables permissionless cleanup.

**86. Dust Amount Locks Object**

- **D:** Tiny token amount ("dust") remaining in an object prevents it from being closed or cleaned up. Attacker sends dust to all victims' accounts.
- **FP:** Dust threshold defined — amounts below threshold ignored or swept. Force-close mechanism for dust balances. Minimum operation amounts enforced.

**87. Counter/Statistic Drift**

- **D:** Global counters (total_deposits, total_users, total_volume) updated in separate steps from the triggering operation. If counter update is skipped, the counter drifts from reality.
- **FP:** Counters updated atomically with the triggering operation. Counters re-derivable from on-chain state. Counter used for information only (not for critical logic).

**88. BCS Serialization Size Mismatch**

- **D:** Custom BCS (Binary Canonical Serialization) serialization/deserialization has a size mismatch — serialized data doesn't match the expected struct layout. Causes silent data corruption or abort.
- **FP:** Standard BCS used (no custom serialization). Struct layout stable. BCS encoding tested with round-trip verification.

**89. Unsafe `abort` in Library Function**

- **D:** Library function aborts instead of returning an error. Caller has no way to handle the error gracefully — the entire transaction fails, potentially DoS-ing a critical code path.
- **FP:** Library functions return `Option` or custom error type. Abort only on truly unrecoverable conditions. Caller can handle expected failure cases.

**90. Missing Input Validation on Instruction Arguments**

- **D:** Function accepts user-provided arguments without range or sanity checking. Values at boundaries (0, u64::MAX, negative-by-interpretation) cause overflows, underflows, or logic errors.
- **FP:** All arguments validated at function entry. Range checks: `assert!(value >= MIN && value <= MAX)`. Documentation specifies valid ranges.
