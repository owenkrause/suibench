module challenge::lending {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    const ENotLiquidatable: u64 = 0;

    public struct Loan has key {
        id: UID,
        borrower: address,
        collateral: Balance<ASSET>,
        repaid: Balance<ASSET>,
        debt: u64,
    }

    public fun open(collateral: Coin<ASSET>, debt: u64, ctx: &mut TxContext) {
        transfer::share_object(Loan {
            id: object::new(ctx),
            borrower: ctx.sender(),
            collateral: coin::into_balance(collateral),
            repaid: balance::zero(),
            debt,
        });
    }

    public fun liquidate(loan: &mut Loan, repayment: Coin<ASSET>, ctx: &mut TxContext): Coin<ASSET> {
        assert!(loan.debt > balance::value(&loan.collateral), ENotLiquidatable);
        let repay = coin::value(&repayment);
        loan.debt = loan.debt - repay;
        balance::join(&mut loan.repaid, coin::into_balance(repayment));
        let seize = balance::value(&loan.collateral);
        coin::from_balance(balance::split(&mut loan.collateral, seize), ctx)
    }
}
