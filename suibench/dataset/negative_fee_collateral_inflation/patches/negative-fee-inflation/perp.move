module challenge::perp {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};
    use challenge::asset::ASSET;

    const MAX_FEE: u64 = 100000;
    const EFeeTooHigh: u64 = 0;

    public struct Fee has copy, drop {
        magnitude: u64,
        negative: bool,
    }

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct Account has store {
        owner: address,
        collateral: u64,
    }

    public struct Exchange has key {
        id: UID,
        vault: Balance<ASSET>,
        accounts: Table<address, Account>,
        protocol_fees: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Exchange { id: object::new(ctx), vault: balance::zero(), accounts: table::new(ctx), protocol_fees: 0 });
        transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
    }

    public fun open_account(ex: &mut Exchange, ctx: &mut TxContext) {
        table::add(&mut ex.accounts, ctx.sender(), Account { owner: ctx.sender(), collateral: 0 });
    }

    public fun deposit(ex: &mut Exchange, coin: Coin<ASSET>, ctx: &TxContext) {
        let acct = table::borrow_mut(&mut ex.accounts, ctx.sender());
        acct.collateral = acct.collateral + coin::value(&coin);
        balance::join(&mut ex.vault, coin::into_balance(coin));
    }

    public fun make_fee(magnitude: u64, negative: bool): Fee {
        Fee { magnitude, negative }
    }

    public fun settle_fee(ex: &mut Exchange, fee: Fee, ctx: &TxContext) {
        assert!(fee.magnitude <= MAX_FEE, EFeeTooHigh);
        assert!(!fee.negative, EFeeTooHigh);
        let acct = table::borrow_mut(&mut ex.accounts, ctx.sender());
        if (fee.negative) {
            acct.collateral = acct.collateral + fee.magnitude;
        } else {
            acct.collateral = acct.collateral - fee.magnitude;
            ex.protocol_fees = ex.protocol_fees + fee.magnitude;
        }
    }

    public fun collect_fees(_: &AdminCap, ex: &mut Exchange, ctx: &mut TxContext): Coin<ASSET> {
        let amount = ex.protocol_fees;
        ex.protocol_fees = 0;
        coin::from_balance(balance::split(&mut ex.vault, amount), ctx)
    }

    public fun withdraw(ex: &mut Exchange, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        let acct = table::borrow_mut(&mut ex.accounts, ctx.sender());
        acct.collateral = acct.collateral - amount;
        coin::from_balance(balance::split(&mut ex.vault, amount), ctx)
    }
}
