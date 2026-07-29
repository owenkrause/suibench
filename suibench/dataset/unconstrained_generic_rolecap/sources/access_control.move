module challenge::access_control {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    public struct UserRole has drop {}
    public struct AdminRole has drop {}

    public struct RoleCap<phantom R> has key, store {
        id: UID,
    }

    public struct Treasury has key {
        id: UID,
        funds: Balance<ASSET>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Treasury { id: object::new(ctx), funds: balance::zero() });
        transfer::public_transfer(RoleCap<AdminRole> { id: object::new(ctx) }, ctx.sender());
    }

    public fun request_user_cap(ctx: &mut TxContext): RoleCap<UserRole> {
        RoleCap<UserRole> { id: object::new(ctx) }
    }

    public fun grant_admin<R>(_cap: &RoleCap<R>, ctx: &mut TxContext): RoleCap<AdminRole> {
        RoleCap<AdminRole> { id: object::new(ctx) }
    }

    public fun deposit(treasury: &mut Treasury, coin: Coin<ASSET>) {
        balance::join(&mut treasury.funds, coin::into_balance(coin));
    }

    public fun withdraw(_cap: &RoleCap<AdminRole>, treasury: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        coin::from_balance(balance::split(&mut treasury.funds, amount), ctx)
    }
}
