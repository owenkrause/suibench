module challenge::vault {
    use sui::coin::{Self, Coin};
    use sui::tx_context::{Self, TxContext};
    use sui::balance::{Self, Balance};
    use sui::event;
    use sui::object::{Self, UID};
    use sui::transfer;
    use challenge::token::TOKEN;

    const DECIMAL_PRECISION: u64 = 1000;

    struct Vault has key {
        id: UID,
        investment_balance: Balance<TOKEN>,
    }

    struct RefundTicket has key, store {
        id: UID,
        amount: u64,
    }

    struct RefundClaimed has copy, drop {
        actor: address,
        deposited_amount: u64,
        paid_amount: u64,
    }

    public fun open(coin: Coin<TOKEN>, ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            investment_balance: coin::into_balance(coin),
        };
        transfer::share_object(vault);
    }

    public fun invest(vault: &mut Vault, coin: Coin<TOKEN>, ctx: &mut TxContext): RefundTicket {
        let amount = coin::value(&coin);
        balance::join(&mut vault.investment_balance, coin::into_balance(coin));
        RefundTicket { id: object::new(ctx), amount }
    }

    public fun claim_refund(vault: &mut Vault, ticket: RefundTicket, ctx: &mut TxContext): Coin<TOKEN> {
        let amount_to_refund = ticket.amount * DECIMAL_PRECISION;
        let RefundTicket { id, amount } = ticket;
        object::delete(id);
        let refund = coin::take(&mut vault.investment_balance, amount_to_refund, ctx);
        let paid_amount = coin::value(&refund);
        event::emit(RefundClaimed {
            actor: tx_context::sender(ctx),
            deposited_amount: amount,
            paid_amount,
        });
        refund
    }
}
