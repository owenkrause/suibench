module challenge::admin {
    use sui::package::{Self, UpgradeCap};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    const EWrongPackage: u64 = 0;

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

    // FIX: bind the cap to THIS package. `package::upgrade_package` returns the id
    // of the package the UpgradeCap governs; requiring it to equal this package's
    // own id (@challenge, substituted to the real id at publish) rejects the
    // throwaway-package UpgradeCap anyone can mint. Merely holding "an" UpgradeCap
    // is no longer accepted as authority.
    public fun claim_admin(upgrade_cap: &UpgradeCap, ctx: &mut TxContext): AdminCap {
        assert!(package::upgrade_package(upgrade_cap) == object::id_from_address(@challenge), EWrongPackage);
        AdminCap { id: object::new(ctx) }
    }

    public fun deposit(treasury: &mut Treasury, coin: Coin<SUI>) {
        balance::join(&mut treasury.funds, coin::into_balance(coin));
    }

    public fun withdraw(_admin: &AdminCap, treasury: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::from_balance(balance::split(&mut treasury.funds, amount), ctx)
    }
}
