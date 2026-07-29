module challenge::lending {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};

    const EIndexTypeMismatch: u64 = 0;

    public struct Storage has key {
        id: UID,
        supply: Table<u8, u64>,
    }

    public struct Pool<phantom T> has key {
        id: UID,
        index: u8,
        reserve: Balance<T>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Storage { id: object::new(ctx), supply: table::new(ctx) });
    }

    public fun register_pool<T>(storage: &mut Storage, asset_index: u8, funds: Coin<T>, ctx: &mut TxContext) {
        table::add(&mut storage.supply, asset_index, coin::value(&funds));
        transfer::share_object(Pool<T> { id: object::new(ctx), index: asset_index, reserve: coin::into_balance(funds) });
    }

    public fun deposit<T>(storage: &mut Storage, pool: &mut Pool<T>, asset_index: u8, coin: Coin<T>) {
        assert!(asset_index == pool.index, EIndexTypeMismatch);
        let recorded = table::borrow_mut(&mut storage.supply, asset_index);
        *recorded = *recorded + coin::value(&coin);
        balance::join(&mut pool.reserve, coin::into_balance(coin));
    }

    public fun withdraw<T>(storage: &mut Storage, pool: &mut Pool<T>, asset_index: u8, amount: u64, ctx: &mut TxContext): Coin<T> {
        assert!(asset_index == pool.index, EIndexTypeMismatch);
        let recorded = table::borrow_mut(&mut storage.supply, asset_index);
        *recorded = *recorded - amount;
        coin::from_balance(balance::split(&mut pool.reserve, amount), ctx)
    }
}
