module challenge::storage {
    use sui::coin::{Self, Coin};
    use sui::tx_context::{Self, TxContext};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use sui::transfer;
    use challenge::token::TOKEN;

    const EInsufficientBalance: u64 = 0;

    struct Storage has key {
        id: UID,
        reserve: Balance<TOKEN>,
        supply: Table<address, u64>
    }

    public fun open(coin: Coin<TOKEN>, ctx: &mut TxContext) {
        let user = tx_context::sender(ctx);
        let amount = coin::value(&coin);
        let storage = Storage {
            id: object::new(ctx),
            reserve: coin::into_balance(coin),
            supply: table::new<address, u64>(ctx)
        };
        add_supply(&mut storage, user, amount);
        transfer::share_object(storage);
    }

    fun add_supply(storage: &mut Storage, user: address, amount: u64) {
        if (!table::contains(&storage.supply, user)) {
            table::add(&mut storage.supply, user, 0);
        };
        let entry = table::borrow_mut(&mut storage.supply, user);
        *entry = *entry + amount;
    }

    public fun deposit(storage: &mut Storage, coin: Coin<TOKEN>, ctx: &mut TxContext) {
        let user = tx_context::sender(ctx);
        let amount = coin::value(&coin);
        balance::join(&mut storage.reserve, coin::into_balance(coin));
        add_supply(storage, user, amount);
    }

    public fun increase_supply_balance(storage: &mut Storage, amount: u64, ctx: &mut TxContext) {
        let user = tx_context::sender(ctx);
        add_supply(storage, user, amount);
    }

    public fun withdraw(storage: &mut Storage, amount: u64, ctx: &mut TxContext): Coin<TOKEN> {
        let user = tx_context::sender(ctx);
        assert!(table::contains(&storage.supply, user), EInsufficientBalance);
        let entry = table::borrow_mut(&mut storage.supply, user);
        assert!(*entry >= amount, EInsufficientBalance);
        *entry = *entry - amount;
        coin::take(&mut storage.reserve, amount, ctx)
    }
}
