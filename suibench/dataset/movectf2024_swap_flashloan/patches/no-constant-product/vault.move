module challenge::vault{
    use sui::coin::{Self, Coin};
    use sui::tx_context::{Self, TxContext};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, ID, UID};
    use sui::transfer;
    use challenge::coina::{Self, MintA};
    use challenge::coinb::{Self, MintB};

    struct Vault<phantom A, phantom B> has key {
        id: UID,
        coin_a: Balance<A>,
        coin_b: Balance<B>,
        flashed: bool
    }

    struct Receipt {
        id: ID,
        a_to_b: bool,
        repay_amount: u64
    }

    public entry fun initialize<A,B>(capa: MintA<A>, capb: MintB<B>,ctx: &mut TxContext) {
        let vault = Vault<A, B> {
            id: object::new(ctx),
            coin_a: coin::into_balance(coina::mint_for_vault(capa, ctx)),
            coin_b: coin::into_balance(coinb::mint_for_vault(capb, ctx)),
            flashed: false
        };
        transfer::share_object(vault);
    }

    public fun flash<A,B>(vault: &mut Vault<A,B>, amount: u64, a_to_b: bool, ctx: &mut TxContext): (Coin<A>, Coin<B>, Receipt) {
        assert!(!vault.flashed, 1);
        let (coin_a, coin_b) = if (a_to_b) {
        (coin::zero<A>(ctx), coin::from_balance(balance::split(&mut vault.coin_b, amount ), ctx))
        }
        else {
        (coin::from_balance(balance::split(&mut vault.coin_a, amount ), ctx), coin::zero<B>(ctx))
        };

        let receipt = Receipt {
            id: object::id(vault),
            a_to_b,
            repay_amount: amount
        };
        vault.flashed = true;

        (coin_a, coin_b, receipt)

    }

    public fun repay_flash<A,B>(vault: &mut Vault<A,B>, coina: Coin<A>, coinb: Coin<B>, receipt: Receipt) {
        let Receipt {
            id: _,
            a_to_b: a2b,
            repay_amount: amount
        } = receipt;
        if (a2b) {
            assert!(coin::value(&coinb) >= amount, 0);
        } else {
            assert!(coin::value(&coina) >= amount, 1);
        };
        balance::join(&mut vault.coin_a, coin::into_balance(coina));
        balance::join(&mut vault.coin_b, coin::into_balance(coinb));
        vault.flashed = false;
    }

    // FIX: price the swap on the constant-product invariant (x*y=k) instead of the
    // instantaneous reserve ratio. The output is `reserve_out - k/(reserve_in + in)`,
    // so draining the pool requires an ever-growing input and a flash-loan-skewed
    // mid-price no longer lets a tiny input capture the whole reserve. `k` is
    // captured from the reserves BEFORE the deposit and widened to u128 to avoid
    // overflow.
    //
    // The `!flashed` guard is load-bearing: CPMM pricing alone is still drainable
    // because a flash loan can borrow an ENTIRE reserve, making k=0 at swap time so
    // the invariant degenerates and any input takes the whole opposite side. Barring
    // swaps against a pool with a loan outstanding removes that manipulation vector;
    // a legitimate flash user borrows, uses the funds elsewhere, and repays.
    public fun swap_a_to_b<A,B>(vault: &mut Vault<A,B>, coina:Coin<A>, ctx: &mut TxContext): Coin<B> {
            assert!(!vault.flashed, 2);
            let reserve_a = balance::value(&vault.coin_a);
            let reserve_b = balance::value(&vault.coin_b);
            let k = (reserve_a as u128) * (reserve_b as u128);
            coin::put<A>(&mut vault.coin_a, coina);
            let new_reserve_a = balance::value(&vault.coin_a);
            let new_reserve_b = ((k / (new_reserve_a as u128)) as u64);
            let amount_out_B = reserve_b - new_reserve_b;
            coin::take(&mut vault.coin_b, amount_out_B, ctx)
    }

    public fun swap_b_to_a<A,B>(vault: &mut Vault<A,B>, coinb:Coin<B>, ctx: &mut TxContext): Coin<A> {
            assert!(!vault.flashed, 2);
            let reserve_a = balance::value(&vault.coin_a);
            let reserve_b = balance::value(&vault.coin_b);
            let k = (reserve_a as u128) * (reserve_b as u128);
            coin::put<B>(&mut vault.coin_b, coinb);
            let new_reserve_b = balance::value(&vault.coin_b);
            let new_reserve_a = ((k / (new_reserve_b as u128)) as u64);
            let amount_out_A = reserve_a - new_reserve_a;
            coin::take(&mut vault.coin_a, amount_out_A, ctx)
    }
}
