/// Concentrated-liquidity pool for an arbitrary token pair (A, B).
///
/// Liquidity providers choose a price range and deposit tokens proportional
/// to the current sqrt-price.  On withdrawal the provider receives their
/// pro-rata share of pool reserves.
module challenge::pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use challenge::math_utils;

    // ── Errors ──────────────────────────────────────────────────

    const E_INSUFFICIENT_DEPOSIT: u64 = 1;
    const E_ZERO_LIQUIDITY: u64 = 2;
    const E_POOL_EMPTY: u64 = 3;
    const E_SLIPPAGE: u64 = 4;
    const E_INVALID_PRICE_RANGE: u64 = 5;

    /// Q64.64 representation of 1.0.
    const Q64: u128 = 1 << 64;

    // ── Objects ─────────────────────────────────────────────────

    /// Shared pool holding reserves for a token pair.
    public struct Pool<phantom A, phantom B> has key {
        id: UID,
        balance_a: Balance<A>,
        balance_b: Balance<B>,
        sqrt_price: u128,       // current sqrt-price in Q64.64
        total_liquidity: u128,  // aggregate liquidity across all positions
    }

    /// A provider's liquidity position.
    public struct Position has key, store {
        id: UID,
        pool_id: ID,
        liquidity: u128,
        sqrt_price_lower: u128, // lower bound of the position's price range
        sqrt_price_upper: u128, // upper bound
    }

    // ── Pool lifecycle ──────────────────────────────────────────

    /// Create an empty pool.  `initial_sqrt_price` is the starting price
    /// expressed as a Q64.64 fixed-point value.
    public fun create_pool<A, B>(
        initial_sqrt_price: u128,
        ctx: &mut TxContext,
    ) {
        transfer::share_object(Pool<A, B> {
            id: object::new(ctx),
            balance_a: balance::zero(),
            balance_b: balance::zero(),
            sqrt_price: initial_sqrt_price,
            total_liquidity: 0,
        });
    }

    // ── Liquidity operations ────────────────────────────────────

    /// Add concentrated liquidity within [`sqrt_price_lower`, `sqrt_price_upper`].
    ///
    /// The required deposit of token A is derived from the concentrated-
    /// liquidity formula; the caller must supply at least that amount.
    /// Token B is accepted as-is (no computed minimum in this simplified
    /// implementation).
    public fun add_liquidity<A, B>(
        pool: &mut Pool<A, B>,
        liquidity: u128,
        sqrt_price_lower: u128,
        sqrt_price_upper: u128,
        coin_a: Coin<A>,
        coin_b: Coin<B>,
        ctx: &mut TxContext,
    ): Position {
        assert!(liquidity > 0, E_ZERO_LIQUIDITY);
        assert!(sqrt_price_upper > sqrt_price_lower, E_INVALID_PRICE_RANGE);

        // Compute how much of token A is needed for this liquidity amount.
        let required_a = compute_deposit_a(
            liquidity,
            sqrt_price_lower,
            sqrt_price_upper,
        );
        assert!(coin::value(&coin_a) >= required_a, E_INSUFFICIENT_DEPOSIT);

        // Accept the deposited tokens.
        balance::join(&mut pool.balance_a, coin::into_balance(coin_a));
        balance::join(&mut pool.balance_b, coin::into_balance(coin_b));
        pool.total_liquidity = pool.total_liquidity + liquidity;

        Position {
            id: object::new(ctx),
            pool_id: object::id(pool),
            liquidity,
            sqrt_price_lower,
            sqrt_price_upper,
        }
    }

    /// Burn a position and withdraw the provider's pro-rata share of both
    /// reserve balances.
    public fun remove_liquidity<A, B>(
        pool: &mut Pool<A, B>,
        position: Position,
        ctx: &mut TxContext,
    ): (Coin<A>, Coin<B>) {
        let Position {
            id,
            pool_id: _,
            liquidity,
            sqrt_price_lower: _,
            sqrt_price_upper: _,
        } = position;
        object::delete(id);
        assert!(pool.total_liquidity > 0, E_POOL_EMPTY);

        // Pro-rata share of reserves.
        let bal_a = (balance::value(&pool.balance_a) as u256);
        let bal_b = (balance::value(&pool.balance_b) as u256);
        let total = (pool.total_liquidity as u256);
        let liq   = (liquidity as u256);

        let amount_a = ((liq * bal_a / total) as u64);
        let amount_b = ((liq * bal_b / total) as u64);

        pool.total_liquidity = pool.total_liquidity - liquidity;

        (
            coin::take(&mut pool.balance_a, amount_a, ctx),
            coin::take(&mut pool.balance_b, amount_b, ctx),
        )
    }

    // ── Swap ────────────────────────────────────────────────────

    /// Swap token A for token B (constant-product pricing).
    /// Updates the pool's internal sqrt-price.
    public fun swap_a_for_b<A, B>(
        pool: &mut Pool<A, B>,
        coin_in: Coin<A>,
        min_out: u64,
        ctx: &mut TxContext,
    ): Coin<B> {
        let amount_in  = (coin::value(&coin_in) as u128);
        let reserve_a  = (balance::value(&pool.balance_a) as u128);
        let reserve_b  = (balance::value(&pool.balance_b) as u128);

        // x * y = k  →  amount_out = amount_in * reserve_b / (reserve_a + amount_in)
        let amount_out = (amount_in * reserve_b) / (reserve_a + amount_in);
        assert!((amount_out as u64) >= min_out, E_SLIPPAGE);

        balance::join(&mut pool.balance_a, coin::into_balance(coin_in));

        // Update sqrt-price from new reserves.
        let new_a = reserve_a + amount_in;
        let new_b = reserve_b - amount_out;
        pool.sqrt_price = (
            (Q64 as u256) * (new_b as u256) / (new_a as u256) as u128
        );

        coin::take(&mut pool.balance_b, (amount_out as u64), ctx)
    }

    // ── Internal math ───────────────────────────────────────────

    /// Compute the required deposit of token A for `liquidity` units in the
    /// range [`sqrt_price_lower`, `sqrt_price_upper`].
    ///
    /// Concentrated-liquidity formula:
    ///
    ///   delta_a = L * (sqrt_upper - sqrt_lower) * 2^64
    ///             ────────────────────────────────────────
    ///                   sqrt_upper * sqrt_lower
    ///
    /// The 2^64 scaling (via `checked_shl_64`) preserves Q64.64 precision
    /// in the numerator before the final division.
    fun compute_deposit_a(
        liquidity: u128,
        sqrt_price_lower: u128,
        sqrt_price_upper: u128,
    ): u64 {
        let price_diff = sqrt_price_upper - sqrt_price_lower;

        // Numerator before precision shift: L * (sqrt_upper - sqrt_lower)
        let numerator_base = math_utils::full_mul_u128(liquidity, price_diff);

        // Scale up by 2^64 for precision.
        let (numerator, overflowed) = math_utils::checked_shl_64(numerator_base);

        // Denominator: sqrt_upper * sqrt_lower
        let denominator = math_utils::full_mul_u128(sqrt_price_upper, sqrt_price_lower);

        if (overflowed) {
            // Precision fallback — skip the extra shift.
            let result = numerator_base / denominator;
            (result as u64)
        } else {
            let result = math_utils::div_round(numerator, denominator, true);
            (result as u64)
        }
    }

    // ── View functions ──────────────────────────────────────────

    public fun pool_balance_a<A, B>(pool: &Pool<A, B>): u64 {
        balance::value(&pool.balance_a)
    }

    public fun pool_balance_b<A, B>(pool: &Pool<A, B>): u64 {
        balance::value(&pool.balance_b)
    }

    public fun pool_sqrt_price<A, B>(pool: &Pool<A, B>): u128 {
        pool.sqrt_price
    }

    public fun pool_liquidity<A, B>(pool: &Pool<A, B>): u128 {
        pool.total_liquidity
    }

    public fun position_liquidity(pos: &Position): u128 {
        pos.liquidity
    }
}
