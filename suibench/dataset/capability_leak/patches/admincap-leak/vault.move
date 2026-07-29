module challenge::vault {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// Attempted to obtain admin rights without being the deployer.
    const ENotAuthorized: u64 = 0;

    /// Admin capability — only the deployer should have this.
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

    /// Only admin can withdraw. Requires a reference to AdminCap.
    public fun withdraw(
        _admin: &AdminCap,
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        coin::take(&mut vault.balance, amount, ctx)
    }

    /// FIX: an AdminCap must never be mintable on demand. The only legitimate
    /// AdminCap is the single one created in `init` and transferred to the
    /// deployer. There is no on-chain deployer identity stored to check against,
    /// and no legitimate reason to mint a second cap, so this entry point always
    /// aborts — no caller can obtain admin rights this way. Legitimate admins
    /// keep using the init-minted cap they already hold.
    public fun request_admin_status(_ctx: &mut TxContext): AdminCap {
        abort ENotAuthorized
    }

    /// View the vault balance.
    public fun vault_balance(vault: &Vault): u64 {
        balance::value(&vault.balance)
    }
}
