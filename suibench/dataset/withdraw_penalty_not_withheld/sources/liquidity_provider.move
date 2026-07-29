module challenge::liquidity_provider {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    const PENALTY_BPS: u64 = 500;
    const BPS: u64 = 10_000;

    public struct Pool has key {
        id: UID,
        capital: Balance<ASSET>,
        penalty_collected: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Pool { id: object::new(ctx), capital: balance::zero(), penalty_collected: 0 });
    }

    public fun deposit(pool: &mut Pool, coin: Coin<ASSET>) {
        balance::join(&mut pool.capital, coin::into_balance(coin));
    }

    public fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        let penalty = amount * PENALTY_BPS / BPS;
        pool.penalty_collected = pool.penalty_collected + penalty;
        coin::from_balance(balance::split(&mut pool.capital, amount), ctx)
    }
}
