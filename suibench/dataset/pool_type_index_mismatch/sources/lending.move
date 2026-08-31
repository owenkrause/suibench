module challenge::lending {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};

    public struct Storage has key {
        id: UID,
        // Per-depositor positions keyed by (caller, asset_index), so a withdrawal
        // is authorized against the caller's OWN recorded stake. Without this a
        // permissionless `withdraw` would be a free drain of any pool — a separate,
        // more severe bug than the labeled index/type desync.
        positions: Table<PosKey, u64>,
    }

    public struct PosKey has copy, drop, store {
        user: address,
        index: u8,
    }

    public struct Pool<phantom T> has key {
        id: UID,
        reserve: Balance<T>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Storage { id: object::new(ctx), positions: table::new(ctx) });
    }

    public fun register_pool<T>(storage: &mut Storage, asset_index: u8, funds: Coin<T>, ctx: &mut TxContext) {
        credit(storage, ctx.sender(), asset_index, coin::value(&funds));
        transfer::share_object(Pool<T> { id: object::new(ctx), reserve: coin::into_balance(funds) });
    }

    public fun deposit<T>(storage: &mut Storage, pool: &mut Pool<T>, asset_index: u8, coin: Coin<T>, ctx: &TxContext) {
        credit(storage, ctx.sender(), asset_index, coin::value(&coin));
        balance::join(&mut pool.reserve, coin::into_balance(coin));
    }

    public fun withdraw<T>(storage: &mut Storage, pool: &mut Pool<T>, asset_index: u8, amount: u64, ctx: &mut TxContext): Coin<T> {
        // Debits the caller's position at `asset_index` but pays out of `pool.reserve`
        // (type T), never checking that `asset_index` corresponds to T.
        let recorded = table::borrow_mut(&mut storage.positions, PosKey { user: ctx.sender(), index: asset_index });
        *recorded = *recorded - amount;
        coin::from_balance(balance::split(&mut pool.reserve, amount), ctx)
    }

    fun credit(storage: &mut Storage, user: address, asset_index: u8, amount: u64) {
        let key = PosKey { user, index: asset_index };
        if (table::contains(&storage.positions, key)) {
            let recorded = table::borrow_mut(&mut storage.positions, key);
            *recorded = *recorded + amount;
        } else {
            table::add(&mut storage.positions, key, amount);
        }
    }
}
