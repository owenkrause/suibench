module challenge::admin {
    use sui::package::{Self, UpgradeCap};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::sui::SUI;

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct AdminClaim has copy, drop {
        actor: address,
        cap_package: ID,
        admin_cap_id: ID,
    }

    public struct Treasury has key {
        id: UID,
        funds: Balance<SUI>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Treasury { id: object::new(ctx), funds: balance::zero() });
    }

    public fun claim_admin(_upgrade_cap: &UpgradeCap, ctx: &mut TxContext): AdminCap {
        let admin_cap = AdminCap { id: object::new(ctx) };
        event::emit(AdminClaim {
            actor: ctx.sender(),
            cap_package: package::upgrade_package(_upgrade_cap),
            admin_cap_id: object::id(&admin_cap),
        });
        admin_cap
    }

    public fun deposit(treasury: &mut Treasury, coin: Coin<SUI>) {
        balance::join(&mut treasury.funds, coin::into_balance(coin));
    }

    public fun withdraw(_admin: &AdminCap, treasury: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::from_balance(balance::split(&mut treasury.funds, amount), ctx)
    }
}
