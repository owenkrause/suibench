module challenge::game {
    use sui::ed25519;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use std::bcs;
    use std::type_name;

    const EBadSignature: u64 = 0;

    public struct Server has key {
        id: UID,
        pubkey: vector<u8>,
    }

    public struct Game<phantom COIN> has key {
        id: UID,
        reserve: Balance<COIN>,
    }

    // FIX: bind the coin type into the signed message. The authorization the
    // server produces now covers the exact `COIN` it was issued for, so a
    // signature issued for a CHEAP sale can no longer be replayed against a
    // VALUABLE reserve (or any other coin) — its bytes no longer match.
    public struct PackMessage has drop {
        coin_type: vector<u8>,
        pack_id: u64,
        amount: u64,
        nonce: u64,
    }

    public fun create_server(pubkey: vector<u8>, ctx: &mut TxContext) {
        transfer::share_object(Server { id: object::new(ctx), pubkey });
    }

    public fun create_game<COIN>(reserve: Coin<COIN>, ctx: &mut TxContext) {
        transfer::share_object(Game<COIN> { id: object::new(ctx), reserve: coin::into_balance(reserve) });
    }

    public fun sell_pack<COIN>(
        server: &Server,
        game: &mut Game<COIN>,
        pack_id: u64,
        amount: u64,
        nonce: u64,
        signature: vector<u8>,
        ctx: &mut TxContext,
    ): Coin<COIN> {
        let coin_type = *type_name::get<COIN>().borrow_string().as_bytes();
        let msg = PackMessage { coin_type, pack_id, amount, nonce };
        let bytes = bcs::to_bytes(&msg);
        assert!(ed25519::ed25519_verify(&signature, &server.pubkey, &bytes), EBadSignature);
        coin::from_balance(balance::split(&mut game.reserve, amount), ctx)
    }
}
