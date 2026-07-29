module challenge::lock {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::clock::Clock;

    const EWrongOwner: u64 = 0;
    const ELocked: u64 = 1;
    const EAlreadyWithdrawn: u64 = 2;

    /// Milliseconds per second — the unit conversion the original gate omitted.
    const MS_PER_SEC: u64 = 1000;

    /// Shared time-locked vault.
    public struct Vault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
        start_ms: u64,
        lock_duration_secs: u64,
        withdrawn: bool,
    }

    /// Lock funds for `lock_duration_secs` seconds (e.g. 86400 for one day),
    /// starting from the current `Clock` timestamp.
    public fun lock(
        coin: Coin<SUI>,
        lock_duration_secs: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        transfer::share_object(Vault {
            id: object::new(ctx),
            owner: ctx.sender(),
            balance: coin::into_balance(coin),
            start_ms: clock.timestamp_ms(),
            lock_duration_secs,
            withdrawn: false,
        });
    }

    /// Add more funds to an existing vault. Does not reset the timer.
    public fun deposit(vault: &mut Vault, coin: Coin<SUI>) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }

    /// Withdraw the full vault balance once the lock has elapsed.
    public fun withdraw(vault: &mut Vault, clock: &Clock, ctx: &mut TxContext): Coin<SUI> {
        assert!(ctx.sender() == vault.owner, EWrongOwner);
        assert!(!vault.withdrawn, EAlreadyWithdrawn);
        // FIX: `start_ms` and `timestamp_ms()` are milliseconds, but
        // `lock_duration_secs` is seconds. Convert the duration to milliseconds
        // before comparing so the lock lasts the full intended wall-clock time
        // (previously it elapsed ~1000x early).
        assert!(
            clock.timestamp_ms() >= vault.start_ms + vault.lock_duration_secs * MS_PER_SEC,
            ELocked,
        );

        vault.withdrawn = true;
        let amount = balance::value(&vault.balance);
        coin::take(&mut vault.balance, amount, ctx)
    }

    public fun owner(vault: &Vault): address { vault.owner }
    public fun balance_value(vault: &Vault): u64 { balance::value(&vault.balance) }
    public fun start_ms(vault: &Vault): u64 { vault.start_ms }
    public fun lock_duration_secs(vault: &Vault): u64 { vault.lock_duration_secs }
    public fun is_withdrawn(vault: &Vault): bool { vault.withdrawn }
}
