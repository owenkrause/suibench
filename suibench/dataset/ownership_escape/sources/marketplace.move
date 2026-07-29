module challenge::marketplace {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// A generic item that users can list for sale.
    public struct Item has key, store {
        id: UID,
        name: vector<u8>,
        value: u64,
    }

    /// A listing in the marketplace. Holds the item and metadata.
    public struct Listing has key {
        id: UID,
        item_id: ID,
        seller: address,
        price: u64,
        item: Item,
    }

    /// Shared marketplace state.
    public struct Marketplace has key {
        id: UID,
        fee_bps: u64, // basis points
        balance: Balance<SUI>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Marketplace {
            id: object::new(ctx),
            fee_bps: 250, // 2.5% fee
            balance: balance::zero(),
        });
    }

    /// Mint a new item (for testing).
    public fun mint_item(
        name: vector<u8>,
        value: u64,
        ctx: &mut TxContext,
    ): Item {
        Item {
            id: object::new(ctx),
            name,
            value,
        }
    }

    /// List an item for sale. Wraps the item in a shared listing so any buyer
    /// can reference it to purchase or the seller can cancel it.
    public fun list_item(
        item: Item,
        price: u64,
        ctx: &mut TxContext,
    ) {
        let item_id = object::id(&item);
        transfer::share_object(Listing {
            id: object::new(ctx),
            item_id,
            seller: ctx.sender(),
            price,
            item,
        });
    }

    /// Buy a listed item. Pays the seller minus marketplace fee.
    public fun buy_item(
        marketplace: &mut Marketplace,
        listing: Listing,
        mut payment: Coin<SUI>,
        ctx: &mut TxContext,
    ): Item {
        let Listing { id, item_id: _, seller, price, item } = listing;
        object::delete(id);

        assert!(coin::value(&payment) >= price, 0);

        let fee = (price * marketplace.fee_bps) / 10000;
        let fee_coin = coin::split(&mut payment, fee, ctx);
        balance::join(&mut marketplace.balance, coin::into_balance(fee_coin));

        transfer::public_transfer(payment, seller);
        item
    }

    /// Cancel a listing and get the item back.
    public fun cancel_listing(
        listing: Listing,
        ctx: &mut TxContext,
    ): Item {
        let Listing { id, item_id: _, seller: _, price: _, item } = listing;
        object::delete(id);
        item
    }
}
