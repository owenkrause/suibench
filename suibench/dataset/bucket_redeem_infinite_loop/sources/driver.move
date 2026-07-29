// SCAFFOLDING (not the vulnerable code). A minimal harness module that exposes the
// friend-gated bucket entry points as public entry functions so a transaction can
// exercise the borrow/redeem path against a shared Bucket<SUI>. See SOURCE.md.
module challenge::driver {

    use sui::coin::{Self, Coin};
    use sui::clock::Clock;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::option;

    use challenge::bucket::{Self, Bucket};
    use challenge::bucket_oracle::{Self, BucketOracle};

    // A high price so a tiny SUI collateral supports a large BUCK debt: with
    // denominator 1, collateral_value_in_buck = coll_amount * PRICE.
    const PRICE: u64 = 1000;
    const DENOMINATOR: u64 = 1;
    const MIN_COLLATERAL_RATIO: u64 = 110;
    const RECOVERY_MODE_THRESHOLD: u64 = 150;
    const COLLATERAL_DECIMAL: u8 = 9;

    fun init(ctx: &mut TxContext) {
        let bucket = bucket::new<SUI>(
            MIN_COLLATERAL_RATIO,
            RECOVERY_MODE_THRESHOLD,
            COLLATERAL_DECIMAL,
            ctx,
        );
        transfer::public_share_object(bucket);

        let oracle = bucket_oracle::new_oracle(PRICE, DENOMINATOR, ctx);
        transfer::public_share_object(oracle);
    }

    public entry fun borrow(
        bucket: &mut Bucket<SUI>,
        oracle: &BucketOracle,
        clock: &Clock,
        collateral: Coin<SUI>,
        debt: u64,
        ctx: &mut TxContext,
    ) {
        bucket::handle_borrow<SUI>(
            bucket,
            oracle,
            clock,
            coin::into_balance(collateral),
            debt,
            option::none(),
            ctx,
        );
    }

    public entry fun redeem(
        bucket: &mut Bucket<SUI>,
        oracle: &BucketOracle,
        clock: &Clock,
        amount: u64,
        ctx: &mut TxContext,
    ) {
        let out = bucket::handle_redeem<SUI>(
            bucket,
            oracle,
            clock,
            amount,
            option::none(),
        );
        transfer::public_transfer(coin::from_balance(out, ctx), tx_context::sender(ctx));
    }
}
