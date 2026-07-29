module challenge::lending_pool {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    public struct Pool has key {
        id: UID,
        liquidity: Balance<ASSET>,
        total_debt: u64,
        defaulted: u64,
        total_ctokens: u64,
    }

    public struct CTokenReceipt has key, store {
        id: UID,
        amount: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            liquidity: balance::zero(),
            total_debt: 0,
            defaulted: 0,
            total_ctokens: 0,
        });
    }

    public fun deposit(pool: &mut Pool, coin: Coin<ASSET>, ctx: &mut TxContext): CTokenReceipt {
        let amount = coin::value(&coin);
        let backing = balance::value(&pool.liquidity) + pool.total_debt;
        let minted = if (pool.total_ctokens == 0 || backing == 0) {
            amount
        } else {
            amount * pool.total_ctokens / backing
        };
        balance::join(&mut pool.liquidity, coin::into_balance(coin));
        pool.total_ctokens = pool.total_ctokens + minted;
        CTokenReceipt { id: object::new(ctx), amount: minted }
    }

    public fun borrow(pool: &mut Pool, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        pool.total_debt = pool.total_debt + amount;
        coin::from_balance(balance::split(&mut pool.liquidity, amount), ctx)
    }

    public fun record_default(pool: &mut Pool, amount: u64) {
        pool.defaulted = pool.defaulted + amount;
    }

    public fun redeem(pool: &mut Pool, receipt: CTokenReceipt, ctokens: u64, ctx: &mut TxContext): (Coin<ASSET>, CTokenReceipt) {
        let CTokenReceipt { id, amount } = receipt;
        let backing = balance::value(&pool.liquidity) + pool.total_debt;
        let value = ctokens * backing / pool.total_ctokens;
        pool.total_ctokens = pool.total_ctokens - ctokens;
        let payout = coin::from_balance(balance::split(&mut pool.liquidity, value), ctx);
        object::delete(id);
        (payout, CTokenReceipt { id: object::new(ctx), amount: amount - ctokens })
    }
}
