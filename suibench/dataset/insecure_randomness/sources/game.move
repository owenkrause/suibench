module challenge::game {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::random::{Self, Random};

    const EWagerTooSmall: u64 = 0;
    const EInsufficientPool: u64 = 1;

    /// Shared wager pool. Winners are paid `payout_bps / 10000` times their wager.
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
        payout_bps: u64,
    }

    /// Seed a new pool with an initial balance and a payout multiplier
    /// expressed in basis points (e.g. 19000 == 1.9x on a win).
    public fun create_pool(seed: Coin<SUI>, payout_bps: u64, ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            balance: coin::into_balance(seed),
            payout_bps,
        });
    }

    /// Anyone can top up the pool.
    public fun top_up(pool: &mut Pool, coin: Coin<SUI>) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    /// Wager on a single coin-flip draw. Wins pay `payout_bps / 10000` times
    /// the wager; losses return an empty coin.
    public fun play(
        pool: &mut Pool,
        wager: Coin<SUI>,
        r: &Random,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let wager_amount = coin::value(&wager);
        assert!(wager_amount > 0, EWagerTooSmall);

        let payout = (wager_amount * pool.payout_bps) / 10000;
        assert!(balance::value(&pool.balance) >= payout, EInsufficientPool);

        balance::join(&mut pool.balance, coin::into_balance(wager));

        let mut generator = random::new_generator(r, ctx);
        let won = random::generate_bool(&mut generator);

        if (won) {
            coin::take(&mut pool.balance, payout, ctx)
        } else {
            coin::zero(ctx)
        }
    }

    public fun pool_balance(pool: &Pool): u64 { balance::value(&pool.balance) }
    public fun payout_bps(pool: &Pool): u64 { pool.payout_bps }
}
