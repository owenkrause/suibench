module challenge::amm_pool {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};
    use challenge::asset::ASSET;

    const EInsufficientLp: u64 = 0;

    public struct Pool has key {
        id: UID,
        reserve: Balance<ASSET>,
        protocol_fee: u64,
        total_lp: u64,
        lp: Table<address, u64>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            reserve: balance::zero(),
            protocol_fee: 0,
            total_lp: 0,
            lp: table::new(ctx),
        });
    }

    public fun add_liquidity(pool: &mut Pool, coin: Coin<ASSET>, ctx: &TxContext): u64 {
        let amount = coin::value(&coin);
        let lp_backing = balance::value(&pool.reserve) - pool.protocol_fee;
        let minted = if (pool.total_lp == 0 || lp_backing == 0) {
            amount
        } else {
            amount * pool.total_lp / lp_backing
        };
        balance::join(&mut pool.reserve, coin::into_balance(coin));
        pool.total_lp = pool.total_lp + minted;
        let owner = ctx.sender();
        if (table::contains(&pool.lp, owner)) {
            let held = table::borrow_mut(&mut pool.lp, owner);
            *held = *held + minted;
        } else {
            table::add(&mut pool.lp, owner, minted);
        };
        minted
    }

    public fun accrue_fee(pool: &mut Pool, coin: Coin<ASSET>) {
        pool.protocol_fee = pool.protocol_fee + coin::value(&coin);
        balance::join(&mut pool.reserve, coin::into_balance(coin));
    }

    public fun remove_liquidity(pool: &mut Pool, lp_amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        let owner = ctx.sender();
        let held = table::borrow_mut(&mut pool.lp, owner);
        assert!(*held >= lp_amount, EInsufficientLp);
        *held = *held - lp_amount;
        let payout = lp_amount * balance::value(&pool.reserve) / pool.total_lp;
        pool.total_lp = pool.total_lp - lp_amount;
        coin::from_balance(balance::split(&mut pool.reserve, payout), ctx)
    }
}
