# Sui Prover — Formal Verification for Move

The Sui Prover mathematically proves properties of Move functions for ALL possible inputs
using the Boogie verification engine and Z3 SMT solver. If it finds a counterexample,
that's a concrete bug with specific input values. If it proves a property, that property
holds for every possible input — no amount of testing can achieve this.

GitHub: https://github.com/asymptotic-code/sui-prover
Install: `brew install asymptotic-code/sui-prover/sui-prover`

---

## Setup Workflow

The prover runs on a Move package. To add specs to a target package:

### Step 1: Copy the package (don't modify the original)

```bash
cp -r target/ spec-package/
```

### Step 2: Fix Move.toml for implicit dependencies

The Sui Prover requires implicit dependencies. Remove any direct Sui/MoveStdlib deps:

```bash
# In spec-package/Move.toml, delete lines like:
# Sui = { git = "https://github.com/MystenLabs/sui.git", ... }
# MoveStdlib = { git = "...", ... }
```

If the package absolutely needs direct Sui deps, create a separate spec package that
depends on the original. See: https://info.asymptotic.tech/sui-prover-faq

### Step 3: Write spec files in `spec-package/sources/`

### Step 4: Run the prover

```bash
cd spec-package && sui-prover
```

---

## Syntax Reference

### Imports

```move
#[spec_only]
use prover::prover::{requires, ensures, asserts, old};

// Only if using ghost variables:
#[spec_only]
use prover::ghost::{declare_global, declare_global_mut, global};
```

### Spec Function Structure

```move
#[spec(prove)]
fun function_name_spec(/* same args as original */): /* same return type */ {
    // 1. Preconditions (assumed to hold)
    requires(condition);

    // 2. Capture pre-state (for mutable refs)
    let old_obj = old!(obj);

    // 3. Call the function under test
    let result = function_name(args);

    // 4. Postconditions (must hold)
    ensures(condition);

    // 5. Return result
    result
}
```

### Key Functions

| Function | Purpose | Example |
|---|---|---|
| `requires(cond)` | Assume precondition holds | `requires(amount > 0)` |
| `ensures(cond)` | Assert postcondition must hold | `ensures(result <= input)` |
| `asserts(cond)` | Assert condition always holds | `asserts(supply > 0)` |
| `old!(ref)` | Capture pre-state of mutable ref | `let old_pool = old!(pool)` |

### Spec-Only Types

| Method | Converts to | Purpose |
|---|---|---|
| `.to_int()` | Unbounded integer | Avoid overflow in spec math |
| `.to_real()` | Arbitrary-precision real | Check rounding direction |

Unbounded integers support: `.mul()`, `.add()`, `.sub()`, `.div()`, `.lte()`, `.gte()`, `.lt()`, `.gt()`, `.eq()`

### Attributes

| Attribute | Purpose |
|---|---|
| `#[spec(prove)]` | Spec function that the prover will verify |
| `#[spec(prove, focus)]` | Only verify this spec (useful for debugging) |
| `#[spec]` | Spec used as helper/abstraction (not directly verified) |
| `#[spec_only]` | Code visible only to prover (not compiled/tested) |

### Naming Convention

- `<function_name>_spec` — auto-associates with the target function. The prover
  uses the spec instead of the original when verifying other functions that call it.
- Any other name — treated as a standalone scenario (no auto-association).

---

## Spec Templates by Property Type

### Overflow Safety

Verify a math function can't overflow for valid inputs:

```move
#[spec(prove)]
fun checked_shlw_spec(n: u256, shift: u8): u256 {
    // Precondition: inputs within expected range
    requires(shift <= 255);

    let result = checked_shlw(n, shift);

    // The function should never produce a value that wraps
    // For a left shift: result should be n * 2^shift (if it fits)
    // If it doesn't fit, the function should abort
    ensures(result.to_int() >= n.to_int());  // result >= input (no wrap)

    result
}
```

### Multiply-Before-Divide Overflow

Verify a fixed-point multiplication doesn't overflow internally:

```move
#[spec(prove)]
fun mul_spec(a: Number, b: Number): Number {
    // Restrict to values the protocol actually uses
    requires(a.value() <= MAX_EXPECTED_VALUE);
    requires(b.value() <= MAX_EXPECTED_VALUE);

    let result = mul(a, b);

    // Result should be approximately a * b / SCALE
    // Use to_int() to compute without overflow
    let expected = a.value().to_int().mul(b.value().to_int()).div(SCALE.to_int());
    ensures(result.value().to_int() == expected);

    result
}
```

### Share Price Monotonicity

Verify that withdrawals don't decrease the share price:

```move
#[spec(prove)]
fun withdraw_spec<T>(pool: &mut Pool<T>, shares_in: Balance<LP<T>>): Balance<T> {
    requires(shares_in.value() <= pool.shares.supply_value());

    let old_pool = old!(pool);
    let result = withdraw(pool, shares_in);

    let old_balance = old_pool.balance.value().to_int();
    let new_balance = pool.balance.value().to_int();
    let old_shares = old_pool.shares.supply_value().to_int();
    let new_shares = pool.shares.supply_value().to_int();

    // Share price: balance / shares. After withdrawal, price should not decrease.
    // new_balance / new_shares >= old_balance / old_shares
    // Rearranged to avoid division:
    ensures(new_shares.mul(old_balance).lte(old_shares.mul(new_balance)));

    result
}
```

### Rounding Direction (Protocol-Favoring)

Use `.to_real()` to check that truncation favors the protocol:

```move
#[spec(prove)]
fun calculate_fee_spec(amount: u64, fee_bps: u64): u64 {
    requires(fee_bps <= 10000);
    requires(amount > 0);

    let result = calculate_fee(amount, fee_bps);

    // Exact fee (real arithmetic, no truncation)
    let exact_fee = amount.to_real().mul(fee_bps.to_real()).div(10000u64.to_real());

    // Fee should be >= exact (rounds UP = protocol-favoring)
    ensures(result.to_real().gte(exact_fee));

    result
}
```

### Boundary Safety (Comparison Off-by-One)

Verify a boundary check is correct at exact threshold:

```move
#[spec(prove)]
fun validate_shift_spec(n: u256, shift: u8): u256 {
    // Test the exact boundary where overflow becomes possible
    requires(shift == 192);
    requires(n > 0);

    // If the function allows shift=192 with n>0, it should abort.
    // If it doesn't abort, the prover finds a counterexample = bug.
    let result = checked_shlw(n, shift);

    // This ensure should be unreachable if the function correctly aborts
    ensures(false);  // "prove that this line is never reached"

    result
}
```

### Cast Safety

Verify a downcast doesn't truncate:

```move
#[spec(prove)]
fun safe_u64_cast_spec(value: u128): u64 {
    let result = safe_u64_cast(value);

    // Result should equal the original value (no truncation)
    ensures(result.to_int() == value.to_int());

    result
}
```

### State Invariant (Pool Balance Consistency)

```move
#[spec_only]
public fun Pool_inv<T>(self: &Pool<T>): bool {
    // Total shares should be zero iff balance is zero
    if (self.shares.supply_value() == 0) {
        self.balance.value() == 0
    } else {
        self.balance.value() > 0
    }
}
```

### Accumulator Monotonicity

```move
#[spec(prove)]
fun accrue_interest_spec(market: &mut Market, clock: &Clock) {
    let old_market = old!(market);

    accrue_interest(market, clock);

    // Interest index should only increase
    ensures(market.cumulative_index().to_int() >= old_market.cumulative_index().to_int());

    // Last updated should advance
    ensures(market.last_updated() >= old_market.last_updated());
}
```

### Event Correctness (Ghost Variables)

```move
#[spec(prove)]
fun large_withdraw_spec<T>(pool: &mut Pool<T>, shares_in: Balance<LP<T>>): Balance<T> {
    requires(shares_in.value() <= pool.shares.supply_value());

    // Declare ghost variable to track event emission
    declare_global<LargeWithdrawEvent, bool>();

    let shares_amount = shares_in.value();
    let result = withdraw(pool, shares_in);

    // If withdrawal was large, event must have been emitted
    if (shares_amount >= LARGE_THRESHOLD) {
        ensures(*global<LargeWithdrawEvent, bool>());
    };

    result
}
```

### Loop Invariant

When specs involve variables modified in loops, you must provide a loop invariant:

```move
#[spec(prove)]
fun sum_spec(values: &vector<u64>): u64 {
    let result = sum(values);

    ensures(result.to_int() >= 0u64.to_int());

    result
}

// In the original function, add invariant before the loop:
public fun sum(values: &vector<u64>): u64 {
    let total = 0u64;
    let i = 0;

    invariant!(|| {
        ensures(total.to_int() >= 0u64.to_int());
        ensures(i <= values.length());
    });
    while (i < values.length()) {
        total = total + values[i];
        i = i + 1;
    };
    total
}
```

---

## Interpreting Output

### Success

```
Proving: withdraw_spec ... OK
```

The property holds for ALL possible inputs satisfying the `requires` conditions.

### Counterexample

```
Proving: checked_shlw_spec ... FAILED
Counterexample:
  n = 1
  shift = 192
```

A concrete bug. The prover found specific input values that violate the postcondition.
This is a confirmed finding — verify with a dry-run transaction using these exact values.

### Timeout

```
Proving: complex_spec ... TIMEOUT (60s)
```

The prover couldn't prove or disprove within the time limit. Options:
1. **Narrow the `requires`** — restrict input ranges to reduce search space
2. **Use `#[spec(prove, focus)]`** — focus on just this spec
3. **Simplify the postcondition** — break into smaller properties
4. **Add loop invariants** — loops without invariants cause timeouts

### Abort

```
Proving: withdraw_spec ... ABORT (division by zero at line 42)
```

The function can abort for inputs satisfying the `requires`. Either:
- Add a `requires` to exclude the aborting case (if it's an expected precondition)
- Or this IS the bug — the function aborts when it shouldn't

---

## Common Pitfalls

### 1. Missing Loop Invariant

If the spec involves a variable that's modified in a loop, the prover needs a loop
invariant. Without it, the prover assumes the loop could set the variable to anything,
causing spurious failures or timeouts.

### 2. Overly Broad Requires

```move
// BAD — prover must explore all u64 × u64 inputs (huge search space)
requires(true);

// GOOD — restrict to realistic input ranges
requires(amount <= 1_000_000_000_000_000);  // max 1M tokens with 9 decimals
requires(shares > 0);
```

### 3. Direct Sui Dependencies in Move.toml

The prover will fail to compile if Move.toml has direct dependencies like:
```toml
Sui = { git = "https://github.com/MystenLabs/sui.git", ... }
```

Remove these — the prover provides them implicitly.

### 4. Spec Naming Mismatch

If you name your spec `foo_spec` but the function is `bar`, the prover treats it as
a standalone scenario, not a spec of `bar`. It won't be used when verifying callers of `bar`.

### 5. Forgetting to Return Result

The spec function must return the same type as the original. If you forget to return
the result, the prover may give confusing errors.

### 6. Using Regular Math in Postconditions

```move
// BAD — this can overflow in the spec itself
ensures(result <= a * b / c);

// GOOD — use to_int() for unbounded arithmetic
ensures(result.to_int().lte(a.to_int().mul(b.to_int()).div(c.to_int())));
```

---

## Strategy: What to Verify

When auditing a smart contract, prioritize specs for:

1. **All math helper functions** — mul, div, pow, sqrt, shift, cast operations. These are
   small, self-contained, and where off-by-ones hide (Cetus was in a math helper).

2. **Share/rate calculations** — deposit, withdraw, mint, burn. Verify monotonicity
   (share price never decreases) and rounding direction.

3. **Accumulator updates** — interest accrual, reward distribution. Verify monotonicity
   and that the checkpoint advances.

4. **Boundary checks** — any function with explicit comparisons against thresholds.
   Write a spec that tests the exact boundary value.

5. **Cross-type operations** — functions that mix u64/u128/u256 or different decimal scales.
   Verify no precision loss or overflow at realistic values.

Don't try to spec everything — focus on functions where a single wrong comparison or
arithmetic operation could lead to fund loss.
