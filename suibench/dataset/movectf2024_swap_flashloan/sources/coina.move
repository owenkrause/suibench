module challenge::coina {
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};
    use std::option;

    friend challenge::vault;

    struct COINA has drop {}

    struct MintA<phantom COINA> has key, store{
        id: UID,
        cap: TreasuryCap<COINA>
    }

    fun init(witness: COINA, ctx: &mut TxContext){
        let (treasury_cap, metadata) = coin::create_currency<COINA>(witness, 1, b"TKA", b"TKA", b"Token A", option::none(), ctx);
        let mint = MintA<COINA> {
            id: object::new(ctx),
            cap:treasury_cap
        };
        transfer::share_object(mint);
        transfer::public_freeze_object(metadata);
    }

    public(friend) fun mint_for_vault<COINA>(mint: MintA<COINA>, ctx: &mut TxContext): Coin<COINA> {
        let coinb = coin::mint<COINA>(&mut mint.cap, 100, ctx);
        coin::mint_and_transfer(&mut mint.cap, 10, tx_context::sender(ctx), ctx);
        let MintA<COINA> {
            id: ida,
            cap: capa
        } = mint;
        object::delete(ida);
        transfer::public_freeze_object(capa);
        coinb
    }

}
