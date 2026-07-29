/// Minimal single-asset liquidity pool.
///
/// Routes liquidity accounting through `integer_mate::math_u256::checked_shlw`
/// (see `sources/math_u256.move`).
module challenge::pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use integer_mate::math_u256;

    // ── Errors ──────────────────────────────────────────────────

    const E_INSUFFICIENT_DEPOSIT: u64 = 1;
    const E_SHIFT_OVERFLOW: u64 = 2;

    // ── Objects ─────────────────────────────────────────────────

    /// Shared pool holding SUI reserves and aggregate liquidity.
    public struct Pool has key {
        id: UID,
        reserve: Balance<SUI>,
        liquidity: u128,
    }

    // ── Pool lifecycle ──────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            reserve: balance::zero(),
            liquidity: 0,
        });
    }

    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx);
    }

    // ── Liquidity operations ────────────────────────────────────

    /// Add liquidity to the pool. `amount` is a Q128.128-scaled liquidity
    /// notional: `amount >> 128` is the liquidity credited to the pool, and
    /// `amount` is fed through `checked_shlw` to derive the SUI payment
    /// required for that liquidity. The pool trusts `checked_shlw` to flag a
    /// shift that would exceed 256 bits; if it reports no overflow, the scaled
    /// value is used directly to size the required deposit.
    public fun add_liquidity(
        pool: &mut Pool,
        payment: Coin<SUI>,
        amount: u256,
        _ctx: &mut TxContext,
    ) {
        let (scaled, overflowed) = math_u256::checked_shlw(amount);
        assert!(!overflowed, E_SHIFT_OVERFLOW);

        // Descale `scaled` (`amount << 64`) back to a u64 token amount, keeping
        // it aligned with the liquidity descaling below (`amount >> 128`): a
        // correctly-shifted `scaled >> 192` equals `amount >> 128`, so the SUI
        // deposit required tracks the liquidity credited one-for-one.
        let required_payment = ((scaled >> 192) as u64);
        assert!(coin::value(&payment) >= required_payment, E_INSUFFICIENT_DEPOSIT);

        balance::join(&mut pool.reserve, coin::into_balance(payment));

        // Liquidity credited is `amount` descaled to integer units.
        let credited = ((amount >> 128) as u128);
        pool.liquidity = pool.liquidity + credited;
    }

    /// Withdraw `amount` of SUI from the pool's reserves.
    public fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::take(&mut pool.reserve, amount, ctx)
    }

    // ── View functions ──────────────────────────────────────────

    public fun pool_liquidity(pool: &Pool): u128 {
        pool.liquidity
    }

    public fun pool_reserve(pool: &Pool): u64 {
        balance::value(&pool.reserve)
    }
}
