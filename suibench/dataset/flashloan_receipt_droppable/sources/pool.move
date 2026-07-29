module challenge::pool {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    const ERepayTooLittle: u64 = 0;

    public struct Pool has key {
        id: UID,
        funds: Balance<ASSET>,
    }

    public struct FlashLoanReceipt has drop {
        amount: u64,
    }

    public fun create_pool(funds: Coin<ASSET>, ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            funds: coin::into_balance(funds),
        });
    }

    public fun flash_loan(pool: &mut Pool, amount: u64, ctx: &mut TxContext): (Coin<ASSET>, FlashLoanReceipt) {
        let borrowed = coin::from_balance(balance::split(&mut pool.funds, amount), ctx);
        (borrowed, FlashLoanReceipt { amount })
    }

    public fun repay_flash_loan(pool: &mut Pool, coin: Coin<ASSET>, receipt: FlashLoanReceipt) {
        let FlashLoanReceipt { amount } = receipt;
        assert!(coin::value(&coin) >= amount, ERepayTooLittle);
        balance::join(&mut pool.funds, coin::into_balance(coin));
    }
}
