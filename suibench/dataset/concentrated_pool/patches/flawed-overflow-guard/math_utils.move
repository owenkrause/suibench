/// Low-level u256 helpers for fixed-point (Q64.64) arithmetic used by the
/// concentrated-liquidity pool.  Every public function in this module is a
/// pure computation — no on-chain state is read or written.
module challenge::math_utils {

    // ── Full-width multiplication ───────────────────────────────

    /// Multiply two u128 values and return the full 256-bit product.
    public fun full_mul_u128(a: u128, b: u128): u256 {
        (a as u256) * (b as u256)
    }

    // ── Checked left-shift ──────────────────────────────────────

    /// Left-shift a u256 value by 64 bits with overflow detection.
    /// Returns `(shifted_value, did_overflow)`.
    ///
    /// The caller uses this to scale a Q64.64 numerator up by 2^64 before
    /// dividing, which preserves an extra 64 bits of precision in the
    /// quotient.  If the shift would overflow 256 bits the function
    /// returns `(0, true)` so the caller can fall back to a lower-
    /// precision path.
    public fun checked_shl_64(n: u256): (u256, bool) {
        // A left-shift by 64 overflows the 256-bit width iff any bit at
        // position >= 192 is set, i.e. iff `n >= 2^192`.  Guard on that exact
        // boundary rather than on `n > (0xFFFF..FF << 192)`, which lets the
        // window [2^192, 2^256 - 2^192] slip through and wrap silently.
        let overflow_bound = 1u256 << 192;
        if (n >= overflow_bound) {
            (0, true)
        } else {
            ((n << 64), false)
        }
    }

    // ── Rounding division ───────────────────────────────────────

    /// Divide `a` by `b`, optionally rounding up (ceiling division).
    public fun div_round(a: u256, b: u256, round_up: bool): u256 {
        if (round_up) {
            (a + b - 1) / b
        } else {
            a / b
        }
    }
}
