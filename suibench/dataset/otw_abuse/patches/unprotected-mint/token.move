module challenge::token {
    use sui::coin::{Self, TreasuryCap};
    use sui::url;

    /// Attempted to mint without being the authorized admin (deployer).
    const ENotAuthorized: u64 = 0;

    /// The one-time witness type. Named after the module.
    public struct TOKEN has drop {}

    /// Wrapper so we can share the treasury cap.
    public struct TreasuryCapHolder has key {
        id: UID,
        cap: TreasuryCap<TOKEN>,
        /// FIX: record the authorized minter (the deployer) so `mint` can gate
        /// on it. The holder is shared, so without this any caller could mint.
        admin: address,
    }

    /// Module initializer — creates the coin using OTW.
    fun init(witness: TOKEN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            9, // decimals
            b"TKN",
            b"Token",
            b"A sample token",
            option::some(url::new_unsafe_from_bytes(b"https://example.com/icon.png")),
            ctx,
        );

        transfer::public_freeze_object(metadata);

        // Share the treasury cap holder so authorized minters can access it
        transfer::share_object(TreasuryCapHolder {
            id: object::new(ctx),
            cap: treasury_cap,
            // FIX: pin the authorized minter to the deployer.
            admin: ctx.sender(),
        });
    }

    /// Mint new tokens.
    public fun mint(
        holder: &mut TreasuryCapHolder,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        // FIX: only the recorded admin (deployer) may mint. The holder being a
        // shared object no longer implies open minting rights.
        assert!(tx_context::sender(ctx) == holder.admin, ENotAuthorized);
        let coin = coin::mint(&mut holder.cap, amount, ctx);
        transfer::public_transfer(coin, recipient);
    }

    /// Burn tokens.
    public fun burn(
        holder: &mut TreasuryCapHolder,
        coin: coin::Coin<TOKEN>,
    ) {
        coin::burn(&mut holder.cap, coin);
    }

    public fun total_supply(holder: &TreasuryCapHolder): u64 {
        coin::total_supply(&holder.cap)
    }
}
