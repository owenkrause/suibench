module challenge::lending_pool {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use challenge::asset::ASSET;

    const BPS_DENOM: u64 = 10_000;
    const MAX_LTV_BPS: u64 = 8_000;

    const EInsufficientCollateral: u64 = 0;
    const EDebtOutstanding: u64 = 1;
    const EDefaultExceedsDebt: u64 = 2;

    public struct Pool has key {
        id: UID,
        liquidity: Balance<ASSET>,
        collateral: Balance<ASSET>,
        total_debt: u64,
        defaulted: u64,
        total_ctokens: u64,
    }

    // Authority to originate a protocol loan (used to seed the defaulted-loan
    // scenario). Depositor lending is separate; see `borrow_collateralized`.
    public struct BorrowCap has key, store {
        id: UID,
    }

    public struct CTokenReceipt has key, store {
        id: UID,
        amount: u64,
    }

    public struct DebtReceipt has key, store {
        id: UID,
        debt: u64,
        collateral: u64,
    }

    // Least-privilege authority to record a default. Separate from
    // `BorrowCap`: origination and default-accounting are different
    // operational responsibilities.
    public struct DefaultCap has key, store {
        id: UID,
    }

    /// Emitted by `redeem`, after the payout split and pool-state mutation, so
    /// it commits atomically with the redemption it describes.
    public struct Redemption has copy, drop {
        actor: address,
        ctokens_burned: u64,
        actual_payout: u64,
        fair_written_off_payout: u64,
    }

    /// Emitted by `withdraw_collateral`, after the collateral has been
    /// released, with the receipt's debt as it stood BEFORE this release.
    public struct CollateralRelease has copy, drop {
        actor: address,
        debt_remaining: u64,
        collateral_released: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            liquidity: balance::zero(),
            collateral: balance::zero(),
            total_debt: 0,
            defaulted: 0,
            total_ctokens: 0,
        });
        transfer::transfer(BorrowCap { id: object::new(ctx) }, ctx.sender());
        transfer::transfer(DefaultCap { id: object::new(ctx) }, ctx.sender());
    }

    public fun deposit(pool: &mut Pool, coin: Coin<ASSET>, ctx: &mut TxContext): CTokenReceipt {
        let amount = coin::value(&coin);
        let backing = balance::value(&pool.liquidity) + pool.total_debt;
        let minted = if (pool.total_ctokens == 0 || backing == 0) {
            amount
        } else {
            amount * pool.total_ctokens / backing
        };
        balance::join(&mut pool.liquidity, coin::into_balance(coin));
        pool.total_ctokens = pool.total_ctokens + minted;
        CTokenReceipt { id: object::new(ctx), amount: minted }
    }

    public fun borrow(_cap: &BorrowCap, pool: &mut Pool, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        pool.total_debt = pool.total_debt + amount;
        coin::from_balance(balance::split(&mut pool.liquidity, amount), ctx)
    }

    public fun record_default(_cap: &DefaultCap, pool: &mut Pool, amount: u64) {
        assert!(amount <= pool.total_debt, EDefaultExceedsDebt);
        pool.defaulted = pool.defaulted + amount;
    }

    public fun redeem(pool: &mut Pool, receipt: CTokenReceipt, ctokens: u64, ctx: &mut TxContext): (Coin<ASSET>, CTokenReceipt) {
        let CTokenReceipt { id, amount } = receipt;
        let backing = balance::value(&pool.liquidity) + pool.total_debt;
        let value = ctokens * backing / pool.total_ctokens;
        // Neutral witness value: the socialized payout a written-down rate
        // would honor for this redemption, computed from state BEFORE this
        // redemption mutates it. Every fixture variant computes this
        // identically; only the pool's actual `total_debt` accounting differs
        // between the vulnerable source and the A patch.
        let unwritten_default = if (pool.defaulted < pool.total_debt) {
            pool.defaulted
        } else {
            pool.total_debt
        };
        let fair_backing = balance::value(&pool.liquidity)
            + pool.total_debt
            - unwritten_default;
        let fair_written_off_payout = ctokens * fair_backing / pool.total_ctokens;
        pool.total_ctokens = pool.total_ctokens - ctokens;
        let payout = coin::from_balance(balance::split(&mut pool.liquidity, value), ctx);
        object::delete(id);
        event::emit(Redemption {
            actor: ctx.sender(),
            ctokens_burned: ctokens,
            actual_payout: value,
            fair_written_off_payout,
        });
        (payout, CTokenReceipt { id: object::new(ctx), amount: amount - ctokens })
    }

    public fun borrow_collateralized(pool: &mut Pool, collateral: Coin<ASSET>, amount: u64, ctx: &mut TxContext): (Coin<ASSET>, DebtReceipt) {
        let coll = coin::value(&collateral);
        assert!(amount <= coll * MAX_LTV_BPS / BPS_DENOM, EInsufficientCollateral);
        balance::join(&mut pool.collateral, coin::into_balance(collateral));
        let borrowed = coin::from_balance(balance::split(&mut pool.liquidity, amount), ctx);
        (borrowed, DebtReceipt { id: object::new(ctx), debt: amount, collateral: coll })
    }

    public fun repay(pool: &mut Pool, receipt: &mut DebtReceipt, coin: Coin<ASSET>) {
        let amount = coin::value(&coin);
        receipt.debt = receipt.debt - amount;
        balance::join(&mut pool.liquidity, coin::into_balance(coin));
    }

    public fun withdraw_collateral(pool: &mut Pool, receipt: &mut DebtReceipt, ctx: &mut TxContext): Coin<ASSET> {
        // FIX: collateral is only releasable once the loan is fully repaid.
        assert!(receipt.debt == 0, EDebtOutstanding);
        let debt_remaining = receipt.debt;
        let amount = receipt.collateral;
        receipt.collateral = 0;
        let released = coin::from_balance(balance::split(&mut pool.collateral, amount), ctx);
        event::emit(CollateralRelease {
            actor: ctx.sender(),
            debt_remaining,
            collateral_released: amount,
        });
        released
    }
}
