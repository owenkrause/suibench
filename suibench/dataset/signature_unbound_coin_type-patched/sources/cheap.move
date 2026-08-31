module challenge::cheap {
    use sui::coin::{Self};
    use std::option;

    /// One-time witness for the low-value coin.
    public struct CHEAP has drop {}

    /// Mint a fixed supply to the publisher and permanently freeze the treasury
    /// cap, so total supply is fixed for the lifetime of the package (no further
    /// minting is possible).
    fun init(witness: CHEAP, ctx: &mut TxContext) {
        let (mut cap, metadata) = coin::create_currency<CHEAP>(
            witness, 0, b"CHP", b"CHP", b"Cheap", option::none(), ctx,
        );
        coin::mint_and_transfer(&mut cap, 1000, ctx.sender(), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(cap);
    }
}
