module challenge::spool {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::table::{Self, Table};
    use challenge::asset::ASSET;

    const ENoStake: u64 = 0;

    public struct Spool has key {
        id: UID,
        reward_index: u64,
        total_staked: u64,
        staked_funds: Balance<ASSET>,
        rewards: Balance<ASSET>,
        accounts: Table<address, Account>,
    }

    public struct Account has store {
        staked: u64,
        last_index: u64,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Spool {
            id: object::new(ctx),
            reward_index: 0,
            total_staked: 0,
            staked_funds: balance::zero(),
            rewards: balance::zero(),
            accounts: table::new(ctx),
        });
    }

    public fun stake(spool: &mut Spool, coin: Coin<ASSET>, ctx: &TxContext) {
        let amount = coin::value(&coin);
        balance::join(&mut spool.staked_funds, coin::into_balance(coin));
        spool.total_staked = spool.total_staked + amount;
        table::add(&mut spool.accounts, ctx.sender(), Account { staked: amount, last_index: 0 });
    }

    public fun add_reward(spool: &mut Spool, coin: Coin<ASSET>) {
        assert!(spool.total_staked > 0, ENoStake);
        spool.reward_index = spool.reward_index + coin::value(&coin) / spool.total_staked;
        balance::join(&mut spool.rewards, coin::into_balance(coin));
    }

    public fun claim(spool: &mut Spool, ctx: &mut TxContext): Coin<ASSET> {
        let account = table::borrow_mut(&mut spool.accounts, ctx.sender());
        let owed = account.staked * (spool.reward_index - account.last_index);
        account.last_index = spool.reward_index;
        coin::from_balance(balance::split(&mut spool.rewards, owed), ctx)
    }
}
