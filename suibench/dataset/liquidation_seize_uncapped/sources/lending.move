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

    // Repay debt; once cleared, return collateral and repayments to the borrower.
    public fun repay(loan: &mut Loan, payment: Coin<ASSET>, ctx: &mut TxContext) {
        let amount = coin::value(&payment);
        let applied = if (amount > loan.debt) loan.debt else amount;
        loan.debt = loan.debt - applied;
        balance::join(&mut loan.repaid, coin::into_balance(payment));
        if (loan.debt == 0) {
            let borrower = loan.borrower;
            let c = balance::value(&loan.collateral);
            let r = balance::value(&loan.repaid);
            transfer::public_transfer(coin::from_balance(balance::split(&mut loan.collateral, c), ctx), borrower);
            transfer::public_transfer(coin::from_balance(balance::split(&mut loan.repaid, r), ctx), borrower);
        }
    }

    public fun liquidate(loan: &mut Loan, repayment: Coin<ASSET>, ctx: &mut TxContext): Coin<ASSET> {
        assert!(loan.debt > balance::value(&loan.collateral), ENotLiquidatable);
        let repay = coin::value(&repayment);
        let applied = if (repay > loan.debt) loan.debt else repay;
        loan.debt = loan.debt - applied;
        balance::join(&mut loan.repaid, coin::into_balance(repayment));
        let seize = balance::value(&loan.collateral);
        coin::from_balance(balance::split(&mut loan.collateral, seize), ctx)
    }
}
