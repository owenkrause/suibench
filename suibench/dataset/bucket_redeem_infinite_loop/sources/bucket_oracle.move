module challenge::bucket_oracle {

    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::clock::Clock;

    struct BucketOracle has key, store {
        id: UID,
        price: u64,
        denominator: u64,
    }

    public fun get_price<T>(oracle: &BucketOracle, _clock: &Clock): (u64, u64) {
        (oracle.price, oracle.denominator)
    }

    public fun new_oracle(price: u64, denominator: u64, ctx: &mut TxContext): BucketOracle {
        BucketOracle { id: object::new(ctx), price, denominator }
    }

    #[test_only]
    public fun new_for_testing(price: u64, denominator: u64, ctx: &mut TxContext): BucketOracle {
        BucketOracle { id: object::new(ctx), price, denominator }
    }
}
