module challenge::lending_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};

    /// One-time witness for the pool's asset coin.
    public struct LENDING_POOL has drop {}

    /// The lending pool holding the asset.
    public struct LendingPool has key {
        id: UID,
        balance: Balance<LENDING_POOL>,
    }

    /// Hot potato — must be consumed by `repay` in the same transaction.
    /// Cannot be stored, copied, or dropped.
    public struct FlashLoanReceipt {
        pool_id: ID,
        borrow_amount: u64,
    }

    #[allow(deprecated_usage)]
    fun init(witness: LENDING_POOL, ctx: &mut TxContext) {
        let (mut treasury, metadata) = coin::create_currency(
            witness, 9, b"AST", b"AST", b"", option::none(), ctx
        );
        // Mint the whole supply to the deployer, then freeze the treasury cap and
        // the metadata to fix the supply.
        let minted = coin::mint(&mut treasury, 1_000_000, ctx);
        transfer::public_transfer(minted, ctx.sender());
        transfer::public_freeze_object(treasury);
        transfer::public_freeze_object(metadata);

        transfer::share_object(LendingPool {
            id: object::new(ctx),
            balance: balance::zero(),
        });
    }

    /// Deposit into the pool (liquidity provision).
    public fun provide_liquidity(
        pool: &mut LendingPool,
        coin: Coin<LENDING_POOL>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    /// Borrow via flash loan. Returns the borrowed coin and a receipt.
    /// The receipt must be consumed by `repay` in the same transaction.
    public fun borrow(
        pool: &mut LendingPool,
        amount: u64,
        ctx: &mut TxContext,
    ): (Coin<LENDING_POOL>, FlashLoanReceipt) {
        assert!(balance::value(&pool.balance) >= amount, 0);

        let coin = coin::take(&mut pool.balance, amount, ctx);
        let receipt = FlashLoanReceipt {
            pool_id: object::id(pool),
            borrow_amount: amount,
        };

        (coin, receipt)
    }

    /// Repay a flash loan. Consumes the receipt (hot potato) once the repayment
    /// coin clears the borrowed amount.
    public fun repay(
        pool: &mut LendingPool,
        receipt: FlashLoanReceipt,
        repayment: Coin<LENDING_POOL>,
        _ctx: &mut TxContext,
    ): Coin<LENDING_POOL> {
        let FlashLoanReceipt { pool_id, borrow_amount } = receipt;
        assert!(object::id(pool) == pool_id, 1);
        assert!(coin::value(&repayment) >= borrow_amount, 2);
        repayment
    }

    public fun pool_balance(pool: &LendingPool): u64 {
        balance::value(&pool.balance)
    }
}
