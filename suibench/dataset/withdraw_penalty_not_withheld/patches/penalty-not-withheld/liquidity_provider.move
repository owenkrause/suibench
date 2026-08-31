module challenge::liquidity_provider {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::table::{Self, Table};
    use challenge::asset::ASSET;

    const PENALTY_BPS: u64 = 500;
    const BPS: u64 = 10_000;

    const EInsufficient: u64 = 0;

    public struct Pool has key {
        id: UID,
        capital: Balance<ASSET>,
        // Per-LP principal, so a withdrawal is authorized against the caller's
        // own stake. Without this, `withdraw` would be a free drain of the whole
        // pool — a separate, more severe bug than the labeled one.
        positions: Table<address, u64>,
        penalty_collected: u64,
    }

    /// Neutral receipt for a successful withdrawal. Values are captured after
    /// the payout coin is created, so the event commits atomically with the
    /// transfer it describes.
    public struct WithdrawalSettled has copy, drop {
        actor: address,
        withdrawn_amount: u64,
        penalty_amount: u64,
        payout_amount: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Pool {
            id: object::new(ctx),
            capital: balance::zero(),
            positions: table::new(ctx),
            penalty_collected: 0,
        });
    }

    public fun deposit(pool: &mut Pool, coin: Coin<ASSET>, ctx: &mut TxContext) {
        let sender = ctx.sender();
        let amount = coin::value(&coin);
        balance::join(&mut pool.capital, coin::into_balance(coin));
        if (pool.positions.contains(sender)) {
            let held = pool.positions.borrow_mut(sender);
            *held = *held + amount;
        } else {
            pool.positions.add(sender, amount);
        };
    }

    public fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        let sender = ctx.sender();
        let held = pool.positions.borrow_mut(sender);
        assert!(*held >= amount, EInsufficient);
        *held = *held - amount;

        let penalty = amount * PENALTY_BPS / BPS;
        pool.penalty_collected = pool.penalty_collected + penalty;
        // FIX: withhold the penalty — pay the NET amount, not the gross.
        let payout_amount = amount - penalty;
        let payout = coin::from_balance(balance::split(&mut pool.capital, payout_amount), ctx);
        event::emit(WithdrawalSettled {
            actor: sender,
            withdrawn_amount: amount,
            penalty_amount: penalty,
            payout_amount,
        });
        payout
    }
}
