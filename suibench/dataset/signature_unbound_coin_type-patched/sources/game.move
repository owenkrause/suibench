module challenge::game {
    use sui::ed25519;
    use sui::event;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};
    use std::bcs;
    use std::type_name;

    const EBadSignature: u64 = 0;
    const EWrongServer: u64 = 1;
    const EReplayed: u64 = 2;

    public struct Server has key {
        id: UID,
        pubkey: vector<u8>,
    }

    public struct Game<phantom COIN> has key {
        id: UID,
        server: ID,
        reserve: Balance<COIN>,
        used: Table<u64, bool>,
    }

    // server produces now covers the exact `COIN` it was issued for, so a
    // signature issued for a CHEAP sale can no longer be replayed against a
    // VALUABLE reserve (or any other coin) — its bytes no longer match.
    public struct PackMessage has drop {
        coin_type: vector<u8>,
        pack_id: u64,
        amount: u64,
        owner: address,
    }

    /// The server broadcasts signed pack authorizations on chain; the named
    /// owner redeems one with `sell_pack`. The bytes are public, like all tx data.
    public struct Authorization has copy, drop {
        pack_id: u64,
        amount: u64,
        owner: address,
        signature: vector<u8>,
    }

    public fun publish_authorization(
        pack_id: u64,
        amount: u64,
        owner: address,
        signature: vector<u8>,
    ) {
        event::emit(Authorization { pack_id, amount, owner, signature });
    }

    public fun create_server(pubkey: vector<u8>, ctx: &mut TxContext) {
        transfer::share_object(Server { id: object::new(ctx), pubkey });
    }

    public fun create_game<COIN>(server: &Server, reserve: Coin<COIN>, ctx: &mut TxContext) {
        transfer::share_object(Game<COIN> {
            id: object::new(ctx),
            server: object::id(server),
            reserve: coin::into_balance(reserve),
            used: table::new(ctx),
        });
    }

    public fun sell_pack<COIN>(
        server: &Server,
        game: &mut Game<COIN>,
        pack_id: u64,
        amount: u64,
        signature: vector<u8>,
        ctx: &mut TxContext,
    ): Coin<COIN> {
        // A game is payable only by the server it was created with, so a
        // permissionless `create_server` cannot be pointed at someone else's
        // reserve.
        assert!(object::id(server) == game.server, EWrongServer);

        // `owner` comes from the sender, never the caller's arguments, so an
        // authorization is redeemable only by the buyer it was issued to.
        let coin_type = *type_name::with_defining_ids<COIN>().as_string().as_bytes();
        let msg = PackMessage { coin_type, pack_id, amount, owner: ctx.sender() };
        let bytes = bcs::to_bytes(&msg);
        assert!(ed25519::ed25519_verify(&signature, &server.pubkey, &bytes), EBadSignature);

        // Single-use authorization: consume the pack_id so a signature cannot be
        // replayed against this game's reserve.
        assert!(!table::contains(&game.used, pack_id), EReplayed);
        table::add(&mut game.used, pack_id, true);

        coin::from_balance(balance::split(&mut game.reserve, amount), ctx)
    }
}
