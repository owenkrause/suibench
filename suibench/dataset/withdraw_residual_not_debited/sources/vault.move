module challenge::vault {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::table::{Self, Table};

    const RESIDUAL_FEE: u64 = 100;
    const EInsufficient: u64 = 0;

    public struct Vault has key {
        id: UID,
        funds: Balance<SUI>,
        treasury: Balance<SUI>,
        balances: Table<address, u64>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Vault {
            id: object::new(ctx),
            funds: balance::zero(),
            treasury: balance::zero(),
            balances: table::new(ctx),
        });
    }

    public fun deposit(vault: &mut Vault, coin: Coin<SUI>, ctx: &TxContext) {
        let amount = coin::value(&coin);
        balance::join(&mut vault.funds, coin::into_balance(coin));
        let sender = ctx.sender();
        if (table::contains(&vault.balances, sender)) {
            let bal = table::borrow_mut(&mut vault.balances, sender);
            *bal = *bal + amount;
        } else {
            table::add(&mut vault.balances, sender, amount);
        }
    }

    public fun withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        let bal = table::borrow_mut(&mut vault.balances, ctx.sender());
        assert!(*bal >= amount, EInsufficient);
        balance::join(&mut vault.treasury, balance::split(&mut vault.funds, RESIDUAL_FEE));
        *bal = *bal - amount;
        coin::from_balance(balance::split(&mut vault.funds, amount), ctx)
    }
}
