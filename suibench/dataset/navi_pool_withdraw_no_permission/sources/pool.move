module challenge::pool {
    use sui::coin::{Self, Coin};
    use sui::tx_context::{Self, TxContext};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::transfer;
    use challenge::token::TOKEN;

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
        coin::take(&mut pool.funds, amount, ctx)
    }
}
