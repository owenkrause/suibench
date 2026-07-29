module challenge::coinb {
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};
    use std::option;

    friend challenge::vault;

    struct COINB has drop {}

    struct MintB<phantom COINB> has key, store {
        id: UID,
        cap: TreasuryCap<COINB>
    }

    fun init(witness: COINB, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency<COINB>(witness, 1, b"TKB", b"TKB", b"Token B", option::none(), ctx);
        let mint = MintB<COINB> {
            id: object::new(ctx),
            cap:treasury_cap
        };
        transfer::share_object(mint);
        transfer::public_freeze_object(metadata);
    }

    public(friend) fun mint_for_vault<COINB>(mint: MintB<COINB>, ctx: &mut TxContext): Coin<COINB> {
        let coinb = coin::mint<COINB>(&mut mint.cap, 100, ctx);
        coin::mint_and_transfer(&mut mint.cap, 10, tx_context::sender(ctx), ctx);
        let MintB<COINB> {
            id: idb,
            cap: capb
        } = mint;
        object::delete(idb);
        transfer::public_freeze_object(capb);
        coinb
    }

}
