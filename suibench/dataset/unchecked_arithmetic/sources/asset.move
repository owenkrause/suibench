module challenge::asset {
    use sui::coin::{Self};

    /// One-time witness for the pool's asset coin.
    public struct ASSET has drop {}

    /// Module initializer: create a fixed-supply currency. The full supply is
    /// minted once to the deployer and both the metadata and the treasury cap are
    /// frozen, so no more ASSET can ever be minted. Total supply is permanently
    /// 1,000,000.
    fun init(witness: ASSET, ctx: &mut TxContext) {
        let (mut treasury_cap, metadata) = coin::create_currency(
            witness,
            9,
            b"AST",
            b"Asset",
            b"Pool asset",
            option::none(),
            ctx,
        );
        coin::mint_and_transfer(&mut treasury_cap, 1_000_000, ctx.sender(), ctx);
        transfer::public_freeze_object(metadata);
        transfer::public_freeze_object(treasury_cap);
    }
}
