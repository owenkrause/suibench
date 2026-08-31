module challenge::val {
    use sui::coin::{Self, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::option;

    public struct VAL has drop {}

    fun init(witness: VAL, ctx: &mut TxContext) {
        let (mut cap, metadata) = coin::create_currency<VAL>(witness, 9, b"VAL", b"VAL", b"Valuable", option::none(), ctx);
        coin::mint_and_transfer(&mut cap, 1000000, tx_context::sender(ctx), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(cap);
    }
}
