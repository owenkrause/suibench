module challenge::vault {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use challenge::asset::ASSET;

    /// A shared vault: depositors pool ASSET and receive proportional shares.
    public struct Vault has key {
        id: UID,
        balance: Balance<ASSET>,
        total_shares: u64,
    }

    /// Owned receipt for a depositor's share of the vault.
    public struct ShareToken has key, store {
        id: UID,
        shares: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Vault {
            id: object::new(ctx),
            balance: balance::zero(),
            total_shares: 0,
        });
    }

    /// floor(a * b / c), widened to u128 to avoid intermediate overflow.
    fun mul_div(a: u64, b: u64, c: u64): u64 {
        (((a as u128) * (b as u128)) / (c as u128)) as u64
    }

    /// Deposit ASSET and receive proportional shares.
    public fun deposit(
        vault: &mut Vault,
        coin: Coin<ASSET>,
        ctx: &mut TxContext,
    ): ShareToken {
        let amount = coin::value(&coin);

        let shares = if (vault.total_shares == 0) {
            amount
        } else {
            mul_div(amount, vault.total_shares, balance::value(&vault.balance))
        };

        balance::join(&mut vault.balance, coin::into_balance(coin));
        vault.total_shares = vault.total_shares + shares;

        ShareToken { id: object::new(ctx), shares }
    }

    /// Burn shares and withdraw proportional ASSET.
    public fun withdraw(
        vault: &mut Vault,
        token: ShareToken,
        ctx: &mut TxContext,
    ): Coin<ASSET> {
        let ShareToken { id, shares } = token;
        object::delete(id);

        let amount = mul_div(shares, balance::value(&vault.balance), vault.total_shares);
        vault.total_shares = vault.total_shares - shares;

        coin::take(&mut vault.balance, amount, ctx)
    }

    public fun vault_balance(vault: &Vault): u64 {
        balance::value(&vault.balance)
    }

    public fun vault_shares(vault: &Vault): u64 {
        vault.total_shares
    }

    public fun share_value(token: &ShareToken): u64 {
        token.shares
    }
}
