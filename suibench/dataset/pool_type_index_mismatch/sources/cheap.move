module challenge::cheap {
    use sui::coin::{Self, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::option;

    public struct CHEAP has drop {}

    fun init(witness: CHEAP, ctx: &mut TxContext) {
        let (mut cap, metadata) = coin::create_currency<CHEAP>(witness, 9, b"CHP", b"CHP", b"Cheap", option::none(), ctx);
        coin::mint_and_transfer(&mut cap, 1000000, tx_context::sender(ctx), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(cap);
    }
}
