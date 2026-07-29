module challenge::asset {
    use sui::coin::{Self, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use std::option;

    public struct ASSET has drop {}

    fun init(witness: ASSET, ctx: &mut TxContext) {
        let (mut cap, metadata) = coin::create_currency<ASSET>(witness, 9, b"AST", b"AST", b"Asset", option::none(), ctx);
        coin::mint_and_transfer(&mut cap, 1000000, tx_context::sender(ctx), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(cap);
    }
}
