module challenge::valuable {
    use sui::coin::{Self};
    use std::option;

    /// One-time witness for the high-value coin.
    public struct VALUABLE has drop {}

    /// Mint a fixed supply to the publisher and permanently freeze the treasury
    /// cap, so total supply is fixed for the lifetime of the package (no further
    /// minting is possible).
    fun init(witness: VALUABLE, ctx: &mut TxContext) {
        let (mut cap, metadata) = coin::create_currency<VALUABLE>(
            witness, 0, b"VAL", b"VAL", b"Valuable", option::none(), ctx,
        );
        coin::mint_and_transfer(&mut cap, 1000, ctx.sender(), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(cap);
    }
}
