module challenge::balance_manager;

use sui::coin::{Self, Coin};

public struct BalanceManager has key, store {
    id: UID,
    owner: address,
}

public struct DepositCap has store {}

public struct WithdrawCap has store {}

public struct TradeCap has store {}

public struct TradeProof has drop {}

public struct DeepBookReferral has key, store {
    id: UID,
}

public fun new_with_custom_owner_and_caps(
    owner: address,
    ctx: &mut TxContext,
): (BalanceManager, DepositCap, WithdrawCap, TradeCap) {
    (
        BalanceManager { id: object::new(ctx), owner },
        DepositCap {},
        WithdrawCap {},
        TradeCap {},
    )
}

public fun deposit_with_cap<T>(
    _self: &mut BalanceManager,
    _cap: &DepositCap,
    coin: Coin<T>,
    _ctx: &mut TxContext,
) {
    coin::destroy_zero(coin);
}

public fun withdraw_with_cap<T>(
    _self: &mut BalanceManager,
    _cap: &WithdrawCap,
    _amount: u64,
    ctx: &mut TxContext,
): Coin<T> {
    coin::zero<T>(ctx)
}

public fun generate_proof_as_trader(
    _self: &BalanceManager,
    _cap: &TradeCap,
    _ctx: &TxContext,
): TradeProof {
    TradeProof {}
}

public fun balance<T>(_self: &BalanceManager): u64 {
    0
}

public fun set_referral(
    _self: &mut BalanceManager,
    _referral: &DeepBookReferral,
    _cap: &TradeCap,
) {}

public fun unset_referral(_self: &mut BalanceManager, _cap: &TradeCap) {}
