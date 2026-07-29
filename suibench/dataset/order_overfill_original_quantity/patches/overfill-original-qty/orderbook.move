module challenge::orderbook {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    public struct Manager has key {
        id: UID,
        owner: address,
        base: Balance<ASSET>,
    }

    public struct Order has key {
        id: UID,
        maker: address,
        quantity: u64,
        filled: u64,
        price: u64,
    }

    public fun open_manager(base: Coin<ASSET>, ctx: &mut TxContext) {
        transfer::share_object(Manager {
            id: object::new(ctx),
            owner: ctx.sender(),
            base: coin::into_balance(base),
        });
    }

    public fun place_order(quantity: u64, price: u64, ctx: &mut TxContext) {
        transfer::share_object(Order {
            id: object::new(ctx),
            maker: ctx.sender(),
            quantity,
            filled: 0,
            price,
        });
    }

    public fun take(order: &mut Order, maker: &mut Manager, take_qty: u64, ctx: &mut TxContext): Coin<ASSET> {
        let remaining = order.quantity - order.filled;
        let fill = if (take_qty <= remaining) { take_qty } else { remaining };
        order.filled = order.filled + fill;
        coin::from_balance(balance::split(&mut maker.base, fill), ctx)
    }
}
