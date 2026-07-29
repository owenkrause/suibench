module challenge::insurance {
    use sui::coin::{Self, Coin};
    use sui::tx_context::{TxContext};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::transfer;
    use challenge::token::TOKEN;

    struct Vault has key {
        id: UID,
        funds: Balance<TOKEN>
    }

    struct InvestCertificate has key, store {
        id: UID,
        amount: u64,
        claimed: bool
    }

    public fun open(coin: Coin<TOKEN>, ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            funds: coin::into_balance(coin)
        };
        transfer::share_object(vault);
    }

    public fun invest(vault: &mut Vault, coin: Coin<TOKEN>, ctx: &mut TxContext): InvestCertificate {
        let amount = coin::value(&coin);
        balance::join(&mut vault.funds, coin::into_balance(coin));
        InvestCertificate {
            id: object::new(ctx),
            amount,
            claimed: false
        }
    }

    public fun claim_refund(vault: &mut Vault, cert: &mut InvestCertificate, ctx: &mut TxContext): Coin<TOKEN> {
        coin::take(&mut vault.funds, cert.amount, ctx)
    }
}
