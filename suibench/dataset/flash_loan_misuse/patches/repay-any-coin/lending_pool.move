module challenge::lending_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};

    /// One-time witness for the pool's asset coin.
    public struct LENDING_POOL has drop {}

    /// The lending pool holding ASSET.
    public struct LendingPool has key {
        id: UID,
        balance: Balance<LENDING_POOL>,
    }

    /// Hot potato — must be consumed by `repay` in the same transaction.
    /// Cannot be stored, copied, or dropped. Records the pool balance floor at
    /// borrow time so `repay` can require the loan be made whole.
    public struct FlashLoanReceipt {
        pool_id: ID,
        borrow_amount: u64,
        balance_before: u64,
    }

    #[allow(deprecated_usage)]
    fun init(witness: LENDING_POOL, ctx: &mut TxContext) {
        let (mut treasury, metadata) = coin::create_currency(
            witness, 9, b"AST", b"AST", b"", option::none(), ctx
        );
        let minted = coin::mint(&mut treasury, 1_000_000, ctx);
        transfer::public_transfer(minted, ctx.sender());
        transfer::public_freeze_object(treasury);
        transfer::public_freeze_object(metadata);

        transfer::share_object(LendingPool {
            id: object::new(ctx),
            balance: balance::zero(),
        });
    }

    /// Deposit ASSET into the pool (liquidity provision).
    public fun provide_liquidity(
        pool: &mut LendingPool,
        coin: Coin<LENDING_POOL>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    /// Borrow ASSET via flash loan. Returns borrowed coin + receipt.
    /// Receipt MUST be consumed by `repay` in the same transaction.
    public fun borrow(
        pool: &mut LendingPool,
        amount: u64,
        ctx: &mut TxContext,
    ): (Coin<LENDING_POOL>, FlashLoanReceipt) {
        let balance_before = balance::value(&pool.balance);
        assert!(balance_before >= amount, 0);

        let coin = coin::take(&mut pool.balance, amount, ctx);
        let receipt = FlashLoanReceipt {
            pool_id: object::id(pool),
            borrow_amount: amount,
            balance_before,
        };

        (coin, receipt)
    }

    /// Repay a flash loan. Consumes the receipt (hot potato).
    ///
    /// FIX: the repayment coin is JOINED back into the pool (the loaned funds are
    /// captured, not handed back), and the pool balance is required to be restored
    /// to at least its pre-borrow floor. Because `borrow` removed `borrow_amount`
    /// from the pool, the only way to bring the pool back to `balance_before` is to
    /// return `borrow_amount` worth of ASSET into it — so the borrowed liquidity
    /// can no longer be kept while satisfying `repay` with a coin that is refunded.
    /// A caller who tries to keep the borrowed coin must instead surrender a coin of
    /// equal value here, netting zero. Returns a (possibly zero) change coin so the
    /// call shape matches the pre-fix `repay`.
    public fun repay(
        pool: &mut LendingPool,
        receipt: FlashLoanReceipt,
        repayment: Coin<LENDING_POOL>,
        ctx: &mut TxContext,
    ): Coin<LENDING_POOL> {
        let FlashLoanReceipt { pool_id, borrow_amount, balance_before } = receipt;
        assert!(object::id(pool) == pool_id, 1);
        assert!(coin::value(&repayment) >= borrow_amount, 2);

        balance::join(&mut pool.balance, coin::into_balance(repayment));
        // The pool must be made whole: at least the pre-borrow floor is restored.
        assert!(balance::value(&pool.balance) >= balance_before, 3);

        coin::zero(ctx)
    }

    public fun pool_balance(pool: &LendingPool): u64 {
        balance::value(&pool.balance)
    }
}
