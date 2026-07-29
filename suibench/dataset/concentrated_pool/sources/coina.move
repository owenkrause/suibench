module challenge::coina {
    use sui::coin::{Self};
    use std::option;

    /// One-time witness for token A.
    public struct COINA has drop {}

    /// Mint a fixed supply of token A to the publisher and permanently freeze
    /// the treasury cap, so total supply is fixed for the lifetime of the
    /// package (no further minting is possible).
    fun init(witness: COINA, ctx: &mut TxContext) {
        let (mut cap, metadata) = coin::create_currency<COINA>(
            witness, 0, b"TKA", b"TKA", b"Token A", option::none(), ctx,
        );
        coin::mint_and_transfer(&mut cap, 110, ctx.sender(), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(cap);
    }
}
