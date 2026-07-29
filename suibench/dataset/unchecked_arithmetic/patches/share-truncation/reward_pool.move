module challenge::reward_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use challenge::asset::ASSET;

    /// A deposit that would round down to zero shares (on an inflated pool).
    const E_ZERO_SHARES: u64 = 0;

    /// A pool that accepts deposits and issues shares.
    /// Rewards are added separately by the admin, increasing
    /// the value of each share.
    public struct RewardPool has key {
        id: UID,
        balance: Balance<ASSET>,
        total_shares: u64,
    }

    /// Represents a depositor's share of the pool.
    public struct ShareToken has key, store {
        id: UID,
        shares: u64,
    }

    /// Admin capability for adding rewards.
    public struct PoolAdmin has key, store {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(
            PoolAdmin { id: object::new(ctx) },
            ctx.sender(),
        );
        transfer::share_object(RewardPool {
            id: object::new(ctx),
            balance: balance::zero(),
            total_shares: 0,
        });
    }

    /// Deposit ASSET and receive proportional shares.
    public fun deposit(
        pool: &mut RewardPool,
        coin: Coin<ASSET>,
        ctx: &mut TxContext,
    ): ShareToken {
        let amount = coin::value(&coin);

        let shares = if (pool.total_shares == 0) {
            amount
        } else {
            (amount * pool.total_shares) / balance::value(&pool.balance)
        };

        // A nonzero deposit must mint at least one share. If the pool balance has
        // been inflated so far above the share supply that the quotient truncates
        // to zero, abort instead of silently gifting the deposit to existing
        // shareholders (the first-depositor / donation attack).
        assert!(shares > 0, E_ZERO_SHARES);

        balance::join(&mut pool.balance, coin::into_balance(coin));
        pool.total_shares = pool.total_shares + shares;

        ShareToken { id: object::new(ctx), shares }
    }

    /// Burn shares and withdraw proportional ASSET.
    public fun withdraw(
        pool: &mut RewardPool,
        token: ShareToken,
        ctx: &mut TxContext,
    ): Coin<ASSET> {
        let ShareToken { id, shares } = token;
        object::delete(id);

        let amount = (shares * balance::value(&pool.balance)) / pool.total_shares;
        pool.total_shares = pool.total_shares - shares;

        coin::take(&mut pool.balance, amount, ctx)
    }

    /// Admin adds rewards to the pool. Increases value of existing shares.
    public fun add_rewards(
        _admin: &PoolAdmin,
        pool: &mut RewardPool,
        coin: Coin<ASSET>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    public fun pool_balance(pool: &RewardPool): u64 {
        balance::value(&pool.balance)
    }

    public fun pool_shares(pool: &RewardPool): u64 {
        pool.total_shares
    }

    public fun share_value(token: &ShareToken): u64 {
        token.shares
    }
}
