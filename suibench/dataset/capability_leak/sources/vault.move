module challenge::vault {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// Administrative capability.
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Shared vault holding SUI tokens.
    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Module initializer — creates one AdminCap for the deployer
    /// and a shared Vault.
    fun init(ctx: &mut TxContext) {
        transfer::transfer(
            AdminCap { id: object::new(ctx) },
            ctx.sender(),
        );
        transfer::share_object(Vault {
            id: object::new(ctx),
            balance: balance::zero(),
        });
    }

    /// Anyone can deposit SUI into the vault.
    public fun deposit(vault: &mut Vault, coin: Coin<SUI>) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }

    /// Withdraw SUI from the vault. Takes an AdminCap by reference.
    public fun withdraw(
        _admin: &AdminCap,
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        coin::take(&mut vault.balance, amount, ctx)
    }

    /// Returns the caller's admin status.
    public fun request_admin_status(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// View the vault balance.
    public fun vault_balance(vault: &Vault): u64 {
        balance::value(&vault.balance)
    }
}
