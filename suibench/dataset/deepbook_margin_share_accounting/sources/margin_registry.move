module challenge::margin_registry;

use challenge::pool::Pool;

public struct MarginRegistry has key {
    id: UID,
}

public(package) fun load_inner(_self: &MarginRegistry) {}

public fun pool_enabled<BaseAsset, QuoteAsset>(
    _self: &MarginRegistry,
    _pool: &Pool<BaseAsset, QuoteAsset>,
): bool {
    true
}

public(package) fun add_margin_manager(
    _self: &mut MarginRegistry,
    _margin_manager_id: ID,
    _ctx: &TxContext,
) {}

public fun can_withdraw(_self: &MarginRegistry, _pool_id: ID, _risk_ratio: u64): bool {
    true
}

public fun can_borrow(_self: &MarginRegistry, _pool_id: ID, _risk_ratio: u64): bool {
    true
}

public fun can_liquidate(_self: &MarginRegistry, _pool_id: ID, _risk_ratio: u64): bool {
    true
}

public fun user_liquidation_reward(_self: &MarginRegistry, _pool_id: ID): u64 {
    0
}

public fun pool_liquidation_reward(_self: &MarginRegistry, _pool_id: ID): u64 {
    0
}

public fun target_liquidation_risk_ratio(_self: &MarginRegistry, _pool_id: ID): u64 {
    0
}
