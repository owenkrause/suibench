module challenge::pool;

use challenge::balance_manager::{BalanceManager, TradeProof};
use sui::clock::Clock;

public struct Pool<phantom BaseAsset, phantom QuoteAsset> has key, store {
    id: UID,
}

public fun id<BaseAsset, QuoteAsset>(self: &Pool<BaseAsset, QuoteAsset>): ID {
    self.id.to_inner()
}

public fun locked_balance<BaseAsset, QuoteAsset>(
    _self: &Pool<BaseAsset, QuoteAsset>,
    _balance_manager: &BalanceManager,
): (u64, u64, u64) {
    (0, 0, 0)
}

public fun cancel_all_orders<BaseAsset, QuoteAsset>(
    _self: &mut Pool<BaseAsset, QuoteAsset>,
    _balance_manager: &mut BalanceManager,
    _trade_proof: &TradeProof,
    _clock: &Clock,
    _ctx: &mut TxContext,
) {}
