module challenge::admin {
    use sui::package::UpgradeCap;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct Treasury has key {
        id: UID,
        funds: Balance<SUI>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Treasury { id: object::new(ctx), funds: balance::zero() });
    }

    public fun claim_admin(_upgrade_cap: &UpgradeCap, ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    public fun deposit(treasury: &mut Treasury, coin: Coin<SUI>) {
        balance::join(&mut treasury.funds, coin::into_balance(coin));
    }

    public fun withdraw(_admin: &AdminCap, treasury: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::from_balance(balance::split(&mut treasury.funds, amount), ctx)
    }
}
