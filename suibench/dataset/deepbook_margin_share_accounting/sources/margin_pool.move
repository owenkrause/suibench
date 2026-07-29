module challenge::margin_pool;

use challenge::math;
use sui::{balance::{Self, Balance}, clock::Clock, coin::Coin};

const ENotEnoughAssetInPool: u64 = 1;

public struct MarginPool<phantom Asset> has key, store {
    id: UID,
    vault: Balance<Asset>,
    // Cumulative share total across ALL borrows from this pool (a pool-global running total),
    // and the cumulative underlying amount those shares represent.
    total_borrow_shares: u64,
    total_borrow: u64,
    allowed_deepbook_pools: vector<ID>,
}

public(package) fun borrow<Asset>(
    self: &mut MarginPool<Asset>,
    amount: u64,
    _clock: &Clock,
    ctx: &mut TxContext,
): (Coin<Asset>, u64, u64) {
    assert!(amount <= self.vault.value(), ENotEnoughAssetInPool);
    // A share is 1:1 with amount in this reduced model; mint `amount` new shares
    // and fold them into the pool-wide cumulative totals.
    self.total_borrow = self.total_borrow + amount;
    self.total_borrow_shares = self.total_borrow_shares + amount;

    (self.vault.split(amount).into_coin(ctx), self.total_borrow, self.total_borrow_shares)
}

public(package) fun repay<Asset>(
    self: &mut MarginPool<Asset>,
    shares: u64,
    coin: Coin<Asset>,
    _clock: &Clock,
) {
    self.total_borrow_shares = self.total_borrow_shares - shares;
    self.vault.join(coin.into_balance());
}

public(package) fun repay_liquidation<Asset>(
    self: &mut MarginPool<Asset>,
    shares: u64,
    coin: Coin<Asset>,
    _clock: &Clock,
): (u64, u64, u64) {
    let amount = shares;
    let coin_value = coin.value();
    self.total_borrow_shares = self.total_borrow_shares - shares;
    let (reward, default) = if (coin_value > amount) {
        (coin_value - amount, 0)
    } else {
        (0, amount - coin_value)
    };
    self.vault.join(coin.into_balance());

    (amount, reward, default)
}

public(package) fun borrow_shares_to_amount<Asset>(
    self: &MarginPool<Asset>,
    shares: u64,
    _clock: &Clock,
): u64 {
    if (self.total_borrow_shares == 0) {
        0
    } else {
        math::div(
            math::mul(shares, self.total_borrow),
            self.total_borrow_shares,
        )
    }
}

public(package) fun id<Asset>(self: &MarginPool<Asset>): ID {
    self.id.to_inner()
}

public fun deepbook_pool_allowed<Asset>(
    self: &MarginPool<Asset>,
    deepbook_pool_id: ID,
): bool {
    self.allowed_deepbook_pools.contains(&deepbook_pool_id)
}

#[allow(unused_function)]
fun new_for_stub<Asset>(ctx: &mut TxContext): MarginPool<Asset> {
    MarginPool<Asset> {
        id: object::new(ctx),
        vault: balance::zero<Asset>(),
        total_borrow_shares: 0,
        total_borrow: 0,
        allowed_deepbook_pools: vector::empty(),
    }
}
