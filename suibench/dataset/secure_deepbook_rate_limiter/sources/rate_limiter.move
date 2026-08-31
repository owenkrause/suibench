/// Token-bucket rate limiter gating withdrawals from a shared pool.
module challenge::rate_limiter;

use std::u128::min;
use sui::balance::{Self, Balance};
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use challenge::asset::ASSET;

const ERateLimited: u64 = 0;

const CAPACITY: u64 = 1_000_000_000;
const REFILL_PER_MS: u64 = 1_000;

public struct RateLimiter has store {
    available: u64,
    last_updated_ms: u64,
    capacity: u64,
    refill_rate_per_ms: u64,
}

public struct Pool has key {
    id: UID,
    funds: Balance<ASSET>,
    limiter: RateLimiter,
}

fun init(ctx: &mut TxContext) {
    transfer::share_object(Pool {
        id: object::new(ctx),
        funds: balance::zero(),
        limiter: RateLimiter {
            available: CAPACITY,
            last_updated_ms: 0,
            capacity: CAPACITY,
            refill_rate_per_ms: REFILL_PER_MS,
        },
    });
}

// === Public Entry Points ===

public fun deposit(pool: &mut Pool, coin: Coin<ASSET>, clock: &Clock) {
    let amount = coin::value(&coin);
    record_deposit(&mut pool.limiter, amount, clock);
    balance::join(&mut pool.funds, coin::into_balance(coin));
}

public fun withdraw(pool: &mut Pool, amount: u64, clock: &Clock, ctx: &mut TxContext): Coin<ASSET> {
    assert!(check_and_record_withdrawal(&mut pool.limiter, amount, clock), ERateLimited);
    coin::from_balance(balance::split(&mut pool.funds, amount), ctx)
}

// === Public View Functions ===

public fun available(pool: &Pool, clock: &Clock): u64 {
    let self = &pool.limiter;
    let now = clock.timestamp_ms();
    let elapsed = if (now > self.last_updated_ms) now - self.last_updated_ms else 0;
    let refilled = (self.available as u128) + (elapsed as u128) * (self.refill_rate_per_ms as u128);
    min(refilled, self.capacity as u128) as u64
}

public fun balance(pool: &Pool): u64 {
    balance::value(&pool.funds)
}

// === Internal Functions ===

fun record_deposit(self: &mut RateLimiter, amount: u64, clock: &Clock) {
    refill(self, clock);
    let new_available = (self.available as u128) + (amount as u128);
    self.available = min(new_available, self.capacity as u128) as u64;
}

fun check_and_record_withdrawal(self: &mut RateLimiter, amount: u64, clock: &Clock): bool {
    refill(self, clock);
    if (amount > self.available) return false;
    self.available = self.available - amount;
    true
}

fun refill(self: &mut RateLimiter, clock: &Clock) {
    let now = clock.timestamp_ms();
    let elapsed = if (now > self.last_updated_ms) now - self.last_updated_ms else 0;
    if (elapsed > 0) {
        let refill_amount = (elapsed as u128) * (self.refill_rate_per_ms as u128);
        let new_available = (self.available as u128) + refill_amount;
        self.available = min(new_available, self.capacity as u128) as u64;
        self.last_updated_ms = now;
    };
}
