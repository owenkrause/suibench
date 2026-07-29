module challenge::deep_pockets {
    use sui::table::{Self, Table};
    use sui::balance::{Self, Balance, Supply};
    use sui::coin::{Self, Coin};

    public struct USD has drop {}
    public struct EUR has drop {}
    public struct FEE has drop {}

    public struct Account has store {
        collateral: u64,
        debt: u64,
    }

    public struct AccountCap has key, store {
        id: UID,
    }

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct SupplyHolder<phantom T> has key {
        id: UID,
        supply: Supply<T>,
    }

    public struct Protocol<phantom T> has key {
        id: UID,
        accounts: Table<ID, Account>,
        vault_collateral: Balance<USD>,
        vault_loan: Balance<EUR>,
        interest_bp: u64,
    }

    fun burn_supply<T>(sup: Supply<T>, ctx: &mut TxContext) {
        transfer::freeze_object(SupplyHolder {
            id: object::new(ctx),
            supply: sup,
        });
    }

    fun init(ctx: &mut TxContext) {
        let mut sup_fee = balance::create_supply(FEE {});
        let fee = coin::from_balance(balance::increase_supply(&mut sup_fee, 1), ctx);
        let extra = coin::from_balance(balance::increase_supply(&mut sup_fee, 1), ctx);
        transfer::public_share_object(extra);
        burn_supply(sup_fee, ctx);

        let mut sup_usd = balance::create_supply(USD {});
        let mut sup_eur = balance::create_supply(EUR {});
        let seed_usd = coin::from_balance(balance::increase_supply(&mut sup_usd, 100), ctx);
        transfer::public_share_object(seed_usd);
        let seed_eur = coin::from_balance(balance::increase_supply(&mut sup_eur, 1000), ctx);

        let AdminCap { id } = create_protocol(FEE {}, fee, seed_eur, ctx);
        object::delete(id);

        burn_supply(sup_usd, ctx);
        burn_supply(sup_eur, ctx);
    }

    public fun create_protocol<T: drop>(_witness: T, fee: Coin<FEE>, initial_loan: Coin<EUR>, ctx: &mut TxContext): AdminCap {
        assert!(coin::value(&fee) == 1, 1);
        transfer::public_freeze_object(fee);
        transfer::share_object(Protocol<T> {
            id: object::new(ctx),
            accounts: table::new(ctx),
            vault_collateral: balance::zero(),
            vault_loan: coin::into_balance(initial_loan),
            interest_bp: 20000,
        });
        AdminCap {
            id: object::new(ctx),
        }
    }

    public fun change_interest<T>(protocol: &mut Protocol<T>, _cap: &AdminCap, interest_bp: u64) {
        protocol.interest_bp = interest_bp;
    }

    public fun create_account<T>(protocol: &mut Protocol<T>, ctx: &mut TxContext): AccountCap {
        let cap = AccountCap {
            id: object::new(ctx),
        };
        table::add(&mut protocol.accounts, object::id(&cap), Account {
            collateral: 0,
            debt: 0,
        });
        cap
    }

    public entry fun create_account_entry<T>(protocol: &mut Protocol<T>, ctx: &mut TxContext) {
        let cap = create_account(protocol, ctx);
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    public fun deposit_collateral<T>(protocol: &mut Protocol<T>, cap: &AccountCap, usd: Coin<USD>) {
        let account = table::borrow_mut(&mut protocol.accounts, object::id(cap));
        account.collateral = account.collateral + coin::value(&usd);
        balance::join(&mut protocol.vault_collateral, coin::into_balance(usd));
    }

    fun check_invariant(account: &Account) {
        assert!(account.debt <= account.collateral * 7000 / 10000, 0);
    }

    public fun withdraw_collateral<T>(protocol: &mut Protocol<T>, cap: &AccountCap, amount: u64, ctx: &mut TxContext): Coin<USD> {
        let account = table::borrow_mut(&mut protocol.accounts, object::id(cap));
        account.collateral = account.collateral - amount;
        check_invariant(account);
        coin::from_balance(balance::split(&mut protocol.vault_collateral, amount), ctx)
    }

    public fun borrow<T>(protocol: &mut Protocol<T>, cap: &AccountCap, amount: u64, ctx: &mut TxContext): Coin<EUR> {
        let account = table::borrow_mut(&mut protocol.accounts, object::id(cap));
        account.debt = account.debt + amount * protocol.interest_bp / 10000;
        check_invariant(account);
        coin::from_balance(balance::split(&mut protocol.vault_loan, amount), ctx)
    }
}
