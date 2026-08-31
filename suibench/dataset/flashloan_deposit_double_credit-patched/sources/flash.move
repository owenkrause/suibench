module challenge::flash {

    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::vec_map::{Self, VecMap};

    public struct FLASH has drop {}

    public struct FlashLender has key {
        id: UID,
        to_lend: Balance<FLASH>,
        last: u64,
        lender: VecMap<address, u64>
    }

    public struct Receipt {
        flash_lender_id: ID,
        amount: u64
    }

    // creat a FlashLender
    public fun create_lend(lend_coin: Coin<FLASH>, ctx: &mut TxContext) {
        let to_lend = coin::into_balance(lend_coin);
        let id = object::new(ctx);
        let mut lender = vec_map::empty<address, u64>();
        let balance = balance::value(&to_lend);
        vec_map::insert(&mut lender, tx_context::sender(ctx), balance);
        let flash_lender = FlashLender { id, to_lend, last: balance, lender };
        transfer::share_object(flash_lender);
    }

    // get the loan
    public fun loan(
        self: &mut FlashLender, amount: u64, ctx: &mut TxContext
    ): (Coin<FLASH>, Receipt) {
        let to_lend = &mut self.to_lend;
        assert!(balance::value(to_lend) >= amount, 0);
        let loan = coin::take(to_lend, amount, ctx);
        let receipt = Receipt { flash_lender_id: object::id(self), amount };

        (loan, receipt)
    }

    // repay coion to FlashLender
    public fun repay(self: &mut FlashLender, payment: Coin<FLASH>) {
        coin::put(&mut self.to_lend, payment)
    }

    // check the amount in FlashLender is correct
    public fun check(self: &mut FlashLender, receipt: Receipt) {
        let Receipt { flash_lender_id, amount: _ } = receipt;
        assert!(object::id(self) == flash_lender_id, 0);
        assert!(balance::value(&self.to_lend) >= self.last, 0);
    }

    // init Flash
    #[allow(deprecated_usage)]
    fun init(witness: FLASH, ctx: &mut TxContext) {
        let (mut treasury, metadata) = coin::create_currency(
            witness, 2, b"FLASH", b"FLASH", b"", option::none(), ctx
        );
        transfer::public_freeze_object(metadata);
        let owner = tx_context::sender(ctx);

        let flash_coin = coin::mint(&mut treasury, 1000, ctx);

        create_lend(flash_coin, ctx);
        transfer::public_transfer(treasury, owner);
    }

    // get  the balance of FlashLender
    public fun balance(self: &mut FlashLender, ctx: &mut TxContext): u64 {
        *vec_map::get(&self.lender, &tx_context::sender(ctx))
    }

    // deposit token to FlashLender
    public fun deposit(
        self: &mut FlashLender, coin: Coin<FLASH>, ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let amount = coin::value(&coin);
        if (vec_map::contains(&self.lender, &sender)) {
            let balance = vec_map::get_mut(&mut self.lender, &sender);
            *balance = *balance + amount;
        } else {
            vec_map::insert(&mut self.lender, sender, amount);
        };
        // is a real liability of the pool, so the flash-loan solvency floor must
        // rise with it. The original bumped only `to_lend` (the refill) while
        // leaving `last` unchanged, so `check`'s `to_lend >= last` gate was
        // satisfied by the very coin the deposit had just promised back to the
        // depositor — a double-count. Raising `last` by the deposited amount ties
        // the gate to the pool's true obligations: after loan(X)->deposit(X) the
        // floor is `last + X`, so `to_lend` (only back to `last`) no longer
        // clears `check`, and the loan+deposit+withdraw drain aborts. A genuine
        // lender's deposit/withdraw round-trip is unaffected (both `to_lend` and
        // `last` move by the same X and net back).
        self.last = self.last + amount;
        coin::put(&mut self.to_lend, coin);
    }

    // withdraw you token from FlashLender
    #[allow(lint(self_transfer))]
    public fun withdraw(
        self: &mut FlashLender,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let owner = tx_context::sender(ctx);
        let balance = vec_map::get_mut(&mut self.lender, &owner);
        assert!(*balance >= amount, 0);
        *balance = *balance - amount;

        // liquidity removes that liability from the pool, so lower the solvency
        // floor by the same amount as the coin leaves `to_lend`. This keeps a
        // legitimate lender's deposit->withdraw round-trip balanced (last returns
        // to its pre-deposit value) without reopening the drain, which is blocked
        // at `check` before any withdraw can run.
        self.last = self.last - amount;

        let to_lend = &mut self.to_lend;
        transfer::public_transfer(coin::take(to_lend, amount, ctx), owner);
    }
}
