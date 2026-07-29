module challenge::pool {
    use sui::coin::{Self, Coin};
    use sui::tx_context::{Self, TxContext};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::transfer;
    use challenge::token::TOKEN;

    const ENotAuthorized: u64 = 0;

    struct Pool has key {
        id: UID,
        funds: Balance<TOKEN>,
        operator: address
    }

    public fun open(coin: Coin<TOKEN>, ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            funds: coin::into_balance(coin),
            operator: tx_context::sender(ctx)
        };
        transfer::share_object(pool);
    }

    public fun deposit(pool: &mut Pool, coin: Coin<TOKEN>) {
        balance::join(&mut pool.funds, coin::into_balance(coin));
    }

    public fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext): Coin<TOKEN> {
        assert!(tx_context::sender(ctx) == pool.operator, ENotAuthorized);
        coin::take(&mut pool.funds, amount, ctx)
    }
}
