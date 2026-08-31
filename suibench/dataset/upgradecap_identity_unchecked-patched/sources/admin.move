module challenge::admin {
    use std::type_name;
    use sui::address;
    use sui::package::{Self, UpgradeCap};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::sui::SUI;

    const EWrongPackage: u64 = 0;

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

    // of the package the UpgradeCap governs; requiring it to equal this package's
    // own id rejects the throwaway-package UpgradeCap anyone can mint. Merely
    // holding "an" UpgradeCap is no longer accepted as authority.
    //
    // The self id is read at RUNTIME from a type defined here. `@challenge` does
    // NOT work: a named address in expression position compiles into the module's
    // CONSTANT POOL, and publish-time substitution rewrites only the self address
    // identifier — so `@challenge` stays 0x0 and the assert aborts for every
    // caller, including the deployer, bricking the Treasury.
    public fun claim_admin(upgrade_cap: &UpgradeCap, ctx: &mut TxContext): AdminCap {
        let self_type = type_name::with_defining_ids<AdminCap>();
        let self_package = address::from_ascii_bytes(self_type.address_string().as_bytes());
        assert!(
            package::upgrade_package(upgrade_cap) == object::id_from_address(self_package),
            EWrongPackage,
        );
        let admin_cap = AdminCap { id: object::new(ctx) };
        event::emit(AdminClaim {
            actor: ctx.sender(),
            cap_package: package::upgrade_package(upgrade_cap),
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
