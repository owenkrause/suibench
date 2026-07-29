module challenge::asset;

use sui::coin;

/// One-time witness for the staking asset. Fixed supply, minted once to the
/// deployer; both the metadata and the treasury cap are frozen so no further
/// units can ever be created.
public struct ASSET has drop {}

fun init(witness: ASSET, ctx: &mut TxContext) {
    let (mut cap, metadata) = coin::create_currency<ASSET>(
        witness,
        9,
        b"AST",
        b"AST",
        b"Staking asset",
        option::none(),
        ctx,
    );
    coin::mint_and_transfer(&mut cap, 1_000_000, ctx.sender(), ctx);
    transfer::public_freeze_object(metadata);
    transfer::public_freeze_object(cap);
}
