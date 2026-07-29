module challenge::liquid_staking {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};
    use challenge::asset::ASSET;

    const EInsufficient: u64 = 0;

    public struct Pool has key {
        id: UID,
        wal: Balance<ASSET>,
        total_wal: u64,
        total_hawal: u64,
        accounts: Table<address, u64>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            wal: balance::zero(),
            total_wal: 0,
            total_hawal: 0,
            accounts: table::new(ctx),
        });
    }

    public fun stake(pool: &mut Pool, coin: Coin<ASSET>, ctx: &TxContext): u64 {
        let amount = coin::value(&coin);
        let minted = if (pool.total_hawal == 0 || pool.total_wal == 0) {
            amount
        } else {
            amount * pool.total_hawal / pool.total_wal
        };
        balance::join(&mut pool.wal, coin::into_balance(coin));
        pool.total_wal = pool.total_wal + amount;
        pool.total_hawal = pool.total_hawal + minted;
        let holder = ctx.sender();
        if (table::contains(&pool.accounts, holder)) {
            let shares = table::borrow_mut(&mut pool.accounts, holder);
            *shares = *shares + minted;
        } else {
            table::add(&mut pool.accounts, holder, minted);
        };
        minted
    }

    public fun redeem(pool: &mut Pool, hawal_amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        let holder = ctx.sender();
        let shares = table::borrow_mut(&mut pool.accounts, holder);
        assert!(*shares >= hawal_amount, EInsufficient);
        // Price the payout against the CURRENT share supply, THEN burn the shares.
        let wal_out = hawal_amount * pool.total_wal / pool.total_hawal;
        *shares = *shares - hawal_amount;
        pool.total_hawal = pool.total_hawal - hawal_amount;
        pool.total_wal = pool.total_wal - wal_out;
        coin::from_balance(balance::split(&mut pool.wal, wal_out), ctx)
    }
}
