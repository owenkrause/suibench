module challenge::lending {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};
    use std::type_name::{Self, TypeName};

    const EIndexTypeMismatch: u64 = 0;

    public struct Storage has key {
        id: UID,
        positions: Table<PosKey, u64>,
        // Canonical type bound to each asset index: an index names exactly one type.
        index_types: Table<u8, TypeName>,
    }

    public struct PosKey has copy, drop, store {
        user: address,
        index: u8,
    }

    public struct Pool<phantom T> has key {
        id: UID,
        index: u8,
        reserve: Balance<T>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Storage {
            id: object::new(ctx),
            positions: table::new(ctx),
            index_types: table::new(ctx),
        });
    }

    public fun register_pool<T>(storage: &mut Storage, asset_index: u8, funds: Coin<T>, ctx: &mut TxContext) {
        bind_index<T>(storage, asset_index);
        credit(storage, ctx.sender(), asset_index, coin::value(&funds));
        transfer::share_object(Pool<T> { id: object::new(ctx), index: asset_index, reserve: coin::into_balance(funds) });
    }

    public fun deposit<T>(storage: &mut Storage, pool: &mut Pool<T>, asset_index: u8, coin: Coin<T>, ctx: &TxContext) {
        assert!(asset_index == pool.index, EIndexTypeMismatch);
        assert_index_type<T>(storage, asset_index);
        credit(storage, ctx.sender(), asset_index, coin::value(&coin));
        balance::join(&mut pool.reserve, coin::into_balance(coin));
    }

    public fun withdraw<T>(storage: &mut Storage, pool: &mut Pool<T>, asset_index: u8, amount: u64, ctx: &mut TxContext): Coin<T> {
        // The index must name this pool AND this pool's type, so the debited
        // position and the disbursed reserve always refer to the same asset —
        // even though register_pool is permissionless.
        assert!(asset_index == pool.index, EIndexTypeMismatch);
        assert_index_type<T>(storage, asset_index);
        let recorded = table::borrow_mut(&mut storage.positions, PosKey { user: ctx.sender(), index: asset_index });
        *recorded = *recorded - amount;
        coin::from_balance(balance::split(&mut pool.reserve, amount), ctx)
    }

    // The first pool at an index fixes that index's type; a later pool of a
    // different type at the same index is refused, so an attacker cannot forge a
    // cheap-typed pool at a valuable index to cross the accounting.
    fun bind_index<T>(storage: &mut Storage, asset_index: u8) {
        let ty = type_name::with_defining_ids<T>();
        if (table::contains(&storage.index_types, asset_index)) {
            assert!(*table::borrow(&storage.index_types, asset_index) == ty, EIndexTypeMismatch);
        } else {
            table::add(&mut storage.index_types, asset_index, ty);
        }
    }

    fun assert_index_type<T>(storage: &Storage, asset_index: u8) {
        assert!(table::contains(&storage.index_types, asset_index), EIndexTypeMismatch);
        assert!(*table::borrow(&storage.index_types, asset_index) == type_name::with_defining_ids<T>(), EIndexTypeMismatch);
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
