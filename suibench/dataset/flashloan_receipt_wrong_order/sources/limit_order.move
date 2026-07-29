module challenge::limit_order {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    const ERepayTooLittle: u64 = 0;
    const ENotMaker: u64 = 1;

    public struct LimitOrder has key {
        id: UID,
        maker: address,
        funds: Balance<ASSET>,
    }

    public struct FlashLoanReceipt {
        order_id: ID,
        repay_amount: u64,
    }

    public fun create_order(funds: Coin<ASSET>, ctx: &mut TxContext) {
        transfer::share_object(LimitOrder { id: object::new(ctx), maker: ctx.sender(), funds: coin::into_balance(funds) });
    }

    public fun flash_loan(order: &mut LimitOrder, amount: u64, ctx: &mut TxContext): (Coin<ASSET>, FlashLoanReceipt) {
        let borrowed = coin::from_balance(balance::split(&mut order.funds, amount), ctx);
        (borrowed, FlashLoanReceipt { order_id: object::id(order), repay_amount: amount })
    }

    public fun repay_flash_loan(order: &mut LimitOrder, coin: Coin<ASSET>, receipt: FlashLoanReceipt) {
        let FlashLoanReceipt { order_id: _, repay_amount } = receipt;
        assert!(coin::value(&coin) >= repay_amount, ERepayTooLittle);
        balance::join(&mut order.funds, coin::into_balance(coin));
    }

    public fun withdraw_order(order: &mut LimitOrder, ctx: &mut TxContext): Coin<ASSET> {
        assert!(ctx.sender() == order.maker, ENotMaker);
        let amount = balance::value(&order.funds);
        coin::from_balance(balance::split(&mut order.funds, amount), ctx)
    }
}
