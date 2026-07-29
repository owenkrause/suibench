module challenge::bottle {

    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use std::option::{Self, Option};
    use sui::clock::Clock;

    use challenge::linked_table::{Self, LinkedTable};
    use challenge::math::mul_factor;
    use challenge::bucket_oracle::{Self, BucketOracle};
    use challenge::constants;

    friend challenge::bucket;

    const EUnsortedInsertion: u64 = 0;
    const ECannotRedeemFromBottle: u64 = 1;
    const EDestroyNonEmptyBottle: u64 = 2;
    const EBottleTooSmall: u64 = 3;
    const EBottleNotExists: u64 = 4;

    struct BottleTable has store, key {
        id: UID,
        table: LinkedTable<address, Bottle>,
        // redistribution
        total_stake: u64,
        total_stake_snapshot: u64,
        total_collateral_snapshot: u64,
        debt_per_unit_stake: u64,
        reward_per_unit_stake: u64,
    }

    struct Bottle has store, key {
        id: UID,
        collateral_amount: u64,
        buck_amount: u64,
        stake_amount: u64,
        reward_coll_snapshot: u64,
        reward_debt_snapshot: u64,
    }

    public(friend) fun new(ctx: &mut TxContext): Bottle {
        Bottle { id: object::new(ctx), collateral_amount: 0, buck_amount: 0, stake_amount: 0, reward_coll_snapshot: 0, reward_debt_snapshot: 0 }
    }

    public(friend) fun new_table(ctx: &mut TxContext): BottleTable {
        BottleTable {
            id: object::new(ctx),
            table: linked_table::new(ctx),
            total_stake: 0,
            total_stake_snapshot: 0,
            total_collateral_snapshot: 0,
            debt_per_unit_stake: 0,
            reward_per_unit_stake: 0,
        }
    }

    public(friend) fun record_borrow(
        bottle: &mut Bottle,
        collateral_amount: u64,
        buck_amount: u64,
    ) {
        bottle.collateral_amount = bottle.collateral_amount + collateral_amount;
        bottle.buck_amount = bottle.buck_amount + buck_amount;
        assert!(bottle.buck_amount >= constants::minimal_bottle_size(), EBottleTooSmall);
    }

    public(friend) fun record_top_up(
        bottle: &mut Bottle,
        collateral_amount: u64,
    ) {
        bottle.collateral_amount = bottle.collateral_amount + collateral_amount;
    }

    public(friend) fun record_repay(bottle: &mut Bottle, repay_amount: u64, if_check_debt: bool): (bool, u64) {
        if (repay_amount >= bottle.buck_amount) {
            let return_sui_amount = bottle.collateral_amount;
            bottle.collateral_amount = 0;
            bottle.buck_amount = 0;
            // fully repaid
            (true, return_sui_amount)
        } else {
            let return_sui_amount = mul_factor(bottle.collateral_amount, repay_amount, bottle.buck_amount);
            bottle.collateral_amount = bottle.collateral_amount - return_sui_amount;
            bottle.buck_amount = bottle.buck_amount - repay_amount;
            if (if_check_debt) {
                assert!(bottle.buck_amount >= constants::minimal_bottle_size(), EBottleTooSmall);
            };
            // not fully repaid
            (false, return_sui_amount)
        }
    }

    public(friend) fun record_repay_capped<T>(bottle: &mut Bottle, repay_amount: u64, oracle: &BucketOracle, clock: &Clock): (bool, u64) {
        if (repay_amount >= bottle.buck_amount) {
            let (price, denominator) = bucket_oracle::get_price<T>(oracle, clock);
            // collateral: at most 110% debt
            let return_sui_amount = mul_factor(repay_amount * 110 / 100, denominator, price);
            bottle.collateral_amount = bottle.collateral_amount - return_sui_amount;
            bottle.buck_amount = 0;
            // fully repaid
            (true, return_sui_amount)
        } else {
            let return_sui_amount = mul_factor(bottle.collateral_amount, repay_amount, bottle.buck_amount);
            bottle.collateral_amount = bottle.collateral_amount - return_sui_amount;
            bottle.buck_amount = bottle.buck_amount - repay_amount;
            // not fully repaid
            (false, return_sui_amount)
        }
    }

    public(friend) fun record_redeem(
        bottle: &mut Bottle,
        redeemed_amount: u64,
        buck_amount: u64,
    ) {
        assert!(bottle.collateral_amount >= redeemed_amount, ECannotRedeemFromBottle);
        bottle.collateral_amount = bottle.collateral_amount - redeemed_amount;
        bottle.buck_amount = bottle.buck_amount - buck_amount;
    }

    public fun destroy_bottle(table: &mut BottleTable, debtor: address) {
        let bottle = remove_bottle(table, debtor);
        let Bottle { id, collateral_amount, buck_amount, stake_amount, reward_coll_snapshot: _, reward_debt_snapshot: _,} = bottle;
        assert!(collateral_amount == 0 && buck_amount == 0, EDestroyNonEmptyBottle);
        object::delete(id);
        table.total_stake = table.total_stake - stake_amount;
    }

    public fun get_table_length(table: &BottleTable): u64 {
        linked_table::length(&table.table)
    }

    public fun bottle_exists(table: &BottleTable, debtor: address): bool {
        linked_table::contains(&table.table, debtor)
    }

    public fun borrow_bottle(table: &BottleTable, debtor: address): &Bottle {
        assert!(linked_table::contains(&table.table, debtor), EBottleNotExists);
        linked_table::borrow(&table.table, debtor)
    }

    public(friend) fun borrow_bottle_mut(table: &mut BottleTable, debtor: address): &mut Bottle {
        assert!(linked_table::contains(&table.table, debtor), EBottleNotExists);
        linked_table::borrow_mut(&mut table.table, debtor)
    }

    public(friend) fun remove_bottle(table: &mut BottleTable, debtor: address): Bottle {
        assert!(linked_table::contains(&table.table, debtor), EBottleNotExists);
        linked_table::remove(&mut table.table, debtor)
    }

    public(friend) fun pop_front(table: &mut BottleTable): (address, Bottle) {
        assert!(option::is_some(linked_table::front(&table.table)), EBottleNotExists);
        linked_table::pop_front(&mut table.table)
    }

    public(friend) fun push_back(table: &mut BottleTable, debtor: address, bottle: Bottle) {
        linked_table::push_back(&mut table.table, debtor, bottle);
    }

    public fun get_lowest_cr_debtor(table: &BottleTable): Option<address> {
        *linked_table::front(&table.table)
    }

    public fun get_bottle_info(table: &BottleTable, bottle: &Bottle): (u64, u64) {
        let pending_coll = bottle.stake_amount * (table.reward_per_unit_stake - bottle.reward_coll_snapshot);
        let pending_debt = bottle.stake_amount * (table.debt_per_unit_stake - bottle.reward_debt_snapshot);
        (bottle.collateral_amount + pending_coll, bottle.buck_amount + pending_debt)
    }

    public fun get_bottle_info_by_debtor(table: &BottleTable, debtor: address): (u64, u64) {
        assert!(linked_table::contains(&table.table, debtor), EBottleNotExists);
        let bottle = borrow_bottle(table, debtor);
        let pending_coll = bottle.stake_amount * (table.reward_per_unit_stake - bottle.reward_coll_snapshot);
        let pending_debt = bottle.stake_amount * (table.debt_per_unit_stake - bottle.reward_debt_snapshot);
        (bottle.collateral_amount + pending_coll, bottle.buck_amount + pending_debt)
    }

    public(friend) fun get_bottle_info_after_update(table: &mut BottleTable, debtor: address): (u64, u64) {
        assert!(linked_table::contains(&table.table, debtor), EBottleNotExists);
        let table_reward_per_unit_stake = table.reward_per_unit_stake;
        let table_debt_per_unit_stake = table.debt_per_unit_stake;
        let bottle = borrow_bottle_mut(table, debtor);
        let pending_coll = bottle.stake_amount * (table_reward_per_unit_stake - bottle.reward_coll_snapshot);
        let pending_debt = bottle.stake_amount * (table_debt_per_unit_stake - bottle.reward_debt_snapshot);
        bottle.collateral_amount = bottle.collateral_amount + pending_coll;
        bottle.buck_amount = bottle.buck_amount + pending_debt;
        bottle.reward_coll_snapshot = table_reward_per_unit_stake;
        bottle.reward_debt_snapshot = table_debt_per_unit_stake;
        (bottle.collateral_amount, bottle.buck_amount)
    }

    public(friend) fun update_snapshot(table: &mut BottleTable, collateral_vault_balance: u64) {
        table.total_stake_snapshot = table.total_stake;
        table.total_collateral_snapshot = collateral_vault_balance;
    }

    public(friend) fun update_stake_and_total_stake(table: &mut BottleTable, bottle: &mut Bottle) {
        let (collateral_amount, _) = get_bottle_info(table, bottle);
        let new_stake_amount = compute_new_stake(table, collateral_amount);
        table.total_stake = table.total_stake + new_stake_amount - bottle.stake_amount;
        bottle.stake_amount = new_stake_amount;
    }

    public(friend) fun update_stake_and_total_stake_by_debtor(table: &mut BottleTable, debtor: address) {
        let (collateral_amount, _) = get_bottle_info_by_debtor(table, debtor);
        let new_stake_amount = compute_new_stake(table, collateral_amount);
        let bottle_stake_amount = borrow_bottle(table, debtor).stake_amount;
        table.total_stake = table.total_stake + new_stake_amount - bottle_stake_amount;
        let bottle = borrow_bottle_mut(table, debtor);
        bottle.stake_amount = new_stake_amount;
    }

    fun compute_new_stake(table: &mut BottleTable, collateral_amount: u64): u64 {
        if (table.total_collateral_snapshot == 0) {
            collateral_amount
        } else {
            collateral_amount * table.total_stake_snapshot / table.total_collateral_snapshot
        }
    }

    public(friend) fun record_redistribution(
        table: &mut BottleTable,
        collateral_amount: u64,
        debt_amount: u64,
    ) {
        table.reward_per_unit_stake = table.reward_per_unit_stake + collateral_amount / table.total_stake;
        table.debt_per_unit_stake = table.debt_per_unit_stake + debt_amount / table.total_stake;
    }

    public(friend) fun insert(
        table: &mut BottleTable,
        debtor: address,
        bottle: Bottle,
        insertion_place: Option<address>,
    ) {
        if (option::is_none(&insertion_place)) {
            let back_debtor_opt = *linked_table::front(&table.table);
            find_upward_and_insert(table, debtor, bottle, back_debtor_opt);
            return
        } else {
            let start_debtor = option::destroy_some(insertion_place);
            assert!(linked_table::contains(&table.table, debtor), EBottleNotExists);
            let start_bottle = linked_table::borrow(&table.table, debtor);
            if (cr_greater(table, &bottle, start_bottle)) {
                let next_debtor = *linked_table::next(&table.table, start_debtor);
                find_upward_and_insert(table, debtor, bottle, next_debtor);
            } else {
                let prev_debtor = *linked_table::prev(&table.table, start_debtor);
                find_downward_and_insert(table, debtor, bottle, prev_debtor);
            }
        }
    }

    fun find_upward_and_insert(
        table: &mut BottleTable,
        debtor: address,
        bottle: Bottle,
        curr_debtor_opt: Option<address>,
    ) {
        while (option::is_some(&curr_debtor_opt)) {
            let curr_debtor = *option::borrow(&curr_debtor_opt);
            let curr_bottle = linked_table::borrow(&table.table, curr_debtor);
            if (cr_less_or_equal(table, &bottle, curr_bottle)) {
                linked_table::insert_front(&mut table.table, curr_debtor_opt, debtor, bottle);
                return
            };
            curr_debtor_opt = *linked_table::next(&table.table, curr_debtor);
        };
        linked_table::insert_front(&mut table.table, curr_debtor_opt, debtor, bottle);
    }

    fun find_downward_and_insert(
        table: &mut BottleTable,
        debtor: address,
        bottle: Bottle,
        curr_debtor_opt: Option<address>,
    ) {
        while (option::is_some(&curr_debtor_opt)) {
            let curr_debtor = *option::borrow(&curr_debtor_opt);
            let curr_bottle = linked_table::borrow(&table.table, curr_debtor);
            if (cr_greater(table, &bottle, curr_bottle)) {
                linked_table::insert_back(&mut table.table, curr_debtor_opt, debtor, bottle);
                return
            };
            curr_debtor_opt = *linked_table::prev(&mut table.table, curr_debtor);
        };
        linked_table::insert_back(&mut table.table, curr_debtor_opt, debtor, bottle);
    }

    public fun cr_greater(table: &BottleTable, bottle: &Bottle, bottle_cmp: &Bottle): bool {
        let (bottle_coll_amount, bottle_buck_amount) = get_bottle_info(table, bottle);
        let (bottle_coll_amount_cmp, bottle_buck_amount_cmp) = get_bottle_info(table, bottle_cmp);
        (bottle_coll_amount as u128) * (bottle_buck_amount_cmp as u128) >
            (bottle_coll_amount_cmp as u128) * (bottle_buck_amount as u128)
    }

    public fun cr_less_or_equal(table: &BottleTable, bottle: &Bottle, bottle_cmp: &Bottle): bool {
        let (bottle_coll_amount, bottle_buck_amount) = get_bottle_info(table, bottle);
        let (bottle_coll_amount_cmp, bottle_buck_amount_cmp) = get_bottle_info(table, bottle_cmp);
        (bottle_coll_amount as u128) * (bottle_buck_amount_cmp as u128) <=
            (bottle_coll_amount_cmp as u128) * (bottle_buck_amount as u128)
    }

    #[test_only]
    public fun print_bottle(bottle: &Bottle) {
        if (bottle.buck_amount == 0) {
            std::debug::print(&0);
        } else {
            std::debug::print(&(mul_factor(bottle.collateral_amount, 100, bottle.buck_amount)));
        };
        std::debug::print(bottle);
    }

    #[test_only]
    public fun check_bottle_order_in_bucket(table: &BottleTable) {
        let debtor_opt = *linked_table::front(&table.table);
        while(option::is_some(&debtor_opt)) {
            let curr_debtor = *option::borrow(&debtor_opt);
            let curr_bottle = linked_table::borrow(&table.table, curr_debtor);
            print_bottle(curr_bottle);
            let next_debtor_opt = linked_table::next(&table.table, curr_debtor);
            if (option::is_some(next_debtor_opt)) {
                let next_debtor = *option::borrow(next_debtor_opt);
                let next_bottle = linked_table::borrow(&table.table, next_debtor);
                assert!(cr_less_or_equal(table, curr_bottle, next_bottle), 0);
            };
            debtor_opt = *next_debtor_opt;
        };
    }

}
