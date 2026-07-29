module challenge::token {
    use sui::coin::{Self, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::option;

    struct TOKEN has drop {}

    fun init(witness: TOKEN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency<TOKEN>(
            witness, 9, b"TKN", b"TKN", b"Pool asset", option::none(), ctx
        );
        coin::mint_and_transfer(&mut treasury_cap, 1000000, tx_context::sender(ctx), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(treasury_cap);
    }
}
