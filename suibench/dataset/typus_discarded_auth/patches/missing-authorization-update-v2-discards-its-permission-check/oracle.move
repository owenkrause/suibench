module challenge::oracle {
    use sui::clock::{Self, Clock};
    use sui::event;

    const VERSION: u64 = 1;

    const E_VERSION_MISMATCH: u64 = 0;
    const E_NOT_AUTHORIZED: u64 = 1;

    public struct Oracle has key {
        id: UID,
        version: u64,
        price: u64,
        twap_price: u64,
        ts_ms: u64,
    }

    public struct UpdateAuthority has key {
        id: UID,
        authority: vector<address>,
    }

    public struct OracleUpdated has copy, drop {
        actor: address,
        previous_price: u64,
        previous_twap_price: u64,
        new_price: u64,
        new_twap_price: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Oracle {
            id: object::new(ctx),
            version: VERSION,
            price: 0,
            twap_price: 0,
            ts_ms: 0,
        });

        let mut authority = vector::empty<address>();
        vector::push_back(&mut authority, tx_context::sender(ctx));
        transfer::share_object(UpdateAuthority {
            id: object::new(ctx),
            authority,
        });
    }

    fun version_check(oracle: &Oracle) {
        assert!(oracle.version == VERSION, E_VERSION_MISMATCH);
    }

    fun update_(
        oracle: &mut Oracle,
        price: u64,
        twap_price: u64,
        clock: &Clock,
        _ctx: &mut TxContext,
    ) {
        oracle.price = price;
        oracle.twap_price = twap_price;
        oracle.ts_ms = clock::timestamp_ms(clock);
    }

    public fun update_v2(
        oracle: &mut Oracle,
        update_authority: &UpdateAuthority,
        price: u64,
        twap_price: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(
            vector::contains(&update_authority.authority, &tx_context::sender(ctx)),
            E_NOT_AUTHORIZED,
        );
        version_check(oracle);
        let previous_price = oracle.price;
        let previous_twap_price = oracle.twap_price;
        update_(oracle, price, twap_price, clock, ctx);
        event::emit(OracleUpdated {
            actor: tx_context::sender(ctx),
            previous_price,
            previous_twap_price,
            new_price: oracle.price,
            new_twap_price: oracle.twap_price,
        });
    }

    public fun price(oracle: &Oracle): u64 { oracle.price }
}
