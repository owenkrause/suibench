module challenge::coinb {
    use sui::coin::{Self};
    use std::option;

    /// One-time witness for token B.
    public struct COINB has drop {}

    /// Mint a fixed supply of token B to the publisher and permanently freeze
    /// the treasury cap, so total supply is fixed for the lifetime of the
    /// package (no further minting is possible).
    fun init(witness: COINB, ctx: &mut TxContext) {
        let (mut cap, metadata) = coin::create_currency<COINB>(
            witness, 0, b"TKB", b"TKB", b"Token B", option::none(), ctx,
        );
        coin::mint_and_transfer(&mut cap, 100, ctx.sender(), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(cap);
    }
}
