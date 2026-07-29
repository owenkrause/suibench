module challenge::market_maker {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};
    use challenge::asset::ASSET;

    const ENotOwner: u64 = 0;

    public struct Account has store {
        owner: address,
        collateral: Balance<ASSET>,
    }

    public struct MarketMaker has key {
        id: UID,
        accounts: Table<address, Account>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(MarketMaker { id: object::new(ctx), accounts: table::new(ctx) });
    }

    public fun open_account(mm: &mut MarketMaker, ctx: &mut TxContext) {
        let owner = ctx.sender();
        table::add(&mut mm.accounts, owner, Account { owner, collateral: balance::zero() });
    }

    public fun deposit(mm: &mut MarketMaker, coin: Coin<ASSET>, ctx: &TxContext) {
        let account = table::borrow_mut(&mut mm.accounts, ctx.sender());
        balance::join(&mut account.collateral, coin::into_balance(coin));
    }

    public fun account_mut(mm: &mut MarketMaker, owner: address): &mut Account {
        table::borrow_mut(&mut mm.accounts, owner)
    }

    // FIX: holding a `&mut Account` is no longer treated as proof of authority —
    // withdraw verifies the caller actually owns the account. A leaked cross-account
    // `&mut` (from the public `account_mut`) can no longer be used to drain someone
    // else's collateral.
    public fun withdraw(account: &mut Account, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        assert!(account.owner == ctx.sender(), ENotOwner);
        coin::from_balance(balance::split(&mut account.collateral, amount), ctx)
    }
}
