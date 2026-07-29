module challenge::bucket {

    use sui::object::{Self, UID};
    use sui::balance::{Self, Balance};
    use sui::tx_context::{Self, TxContext};
    use sui::clock::Clock;
    use sui::math;
    use std::option::{Self, Option};

    use challenge::math::mul_factor;
    use challenge::bucket_oracle::{Self, BucketOracle};
    use challenge::bottle::{Self, Bottle, BottleTable};
    use challenge::constants;

    friend challenge::driver;

    const EBucketLocked: u64 = 0;
    const EBottleNotFound: u64 = 1;
    const ERepayTooMuch: u64 = 2;
    const EFlashFeeNotEnough: u64 = 3;
    const ENotEnoughToRedeem: u64 = 4;
    const EBottleIsNotHealthy: u64 = 5;

    struct Bucket<phantom T> has key, store {
        id: UID,
        // settings
        min_collateral_ratio: u64,
        recovery_mode_threshold: u64,
        collateral_decimal: u8,
        // handle collateral
        collateral_vault: Balance<T>,
        bottle_table: BottleTable,
        // recording
        minted_buck_amount: u64,
        base_rate_fee: u64,
        latest_redemption_time: u64,
        total_flash_loan_amount: u64,
    }

    struct FlashReceipt<phantom T> {
        amount: u64,
        fee: u64,
    }

    public(friend) fun new<T>(
        min_collateral_ratio: u64,
        recovery_mode_threshold: u64,
        collateral_decimal: u8,
        ctx: &mut TxContext,
    ): Bucket<T> {
        Bucket {
            id: object::new(ctx),
            min_collateral_ratio,
            recovery_mode_threshold,
            collateral_decimal,
            collateral_vault: balance::zero(),
            bottle_table: bottle::new_table(ctx),
            minted_buck_amount: 0,
            base_rate_fee: 0,
            latest_redemption_time: 0,
            total_flash_loan_amount: 0,
        }
    }

    public(friend) fun handle_borrow<T>(
        bucket: &mut Bucket<T>,
        oracle: &BucketOracle,
        clock: &Clock,
        collateral_input: Balance<T>,
        buck_output_amount: u64,
        insertion_place: Option<address>,
        ctx: &mut TxContext,
    ) {
        let borrower = tx_context::sender(ctx);
        assert!(is_not_locked(bucket), EBucketLocked);
        let bottle = if(bottle_exists(bucket, borrower)) {
            bottle::get_bottle_info_after_update(&mut bucket.bottle_table, borrower);
            bottle::remove_bottle(&mut bucket.bottle_table, borrower)
        } else {
            bottle::new(ctx)
        };

        let collateral_input_amount = balance::value(&collateral_input);

        bottle::record_borrow(&mut bottle, collateral_input_amount, buck_output_amount);

        // update stake and total stake when create bottle and adjust bottle
        bottle::update_stake_and_total_stake(&mut bucket.bottle_table, &mut bottle);

        bucket.minted_buck_amount = bucket.minted_buck_amount + buck_output_amount;
        balance::join(&mut bucket.collateral_vault, collateral_input);
        assert!(is_healthy_bottle(bucket, oracle, clock, &bottle), EBottleIsNotHealthy);

        bottle::insert(&mut bucket.bottle_table, borrower, bottle, insertion_place);
    }

    public(friend) fun handle_top_up<T>(
        bucket: &mut Bucket<T>,
        collateral_input: Balance<T>,
        debtor: address,
        insertion_place: Option<address>,
    ) {
        assert!(bottle_exists<T>(bucket, debtor), EBottleNotFound);
        bottle::get_bottle_info_after_update(&mut bucket.bottle_table, debtor);
        let bottle = bottle::remove_bottle(&mut bucket.bottle_table, debtor);
        let collateral_amount = balance::value(&collateral_input);
        bottle::record_top_up(&mut bottle, collateral_amount);
        bottle::update_stake_and_total_stake(&mut bucket.bottle_table, &mut bottle);
        bottle::insert(&mut bucket.bottle_table, debtor, bottle, insertion_place);
        balance::join(&mut bucket.collateral_vault, collateral_input);
    }

    public(friend) fun handle_repay<T>(
        bucket: &mut Bucket<T>,
        debtor: address,
        buck_input_amount: u64,
        if_check_debt: bool,
    ): Balance<T> {
        assert!(bottle_exists<T>(bucket, debtor), EBottleNotFound);
        let (_, buck_amount) = bottle::get_bottle_info_after_update(&mut bucket.bottle_table, debtor);
        assert!(buck_amount >= buck_input_amount, ERepayTooMuch);
        let bottle = bottle::borrow_bottle_mut(&mut bucket.bottle_table, debtor);
        let (is_fully_repaid, return_amount) = bottle::record_repay(bottle, buck_input_amount, if_check_debt);
        bottle::update_stake_and_total_stake_by_debtor(&mut bucket.bottle_table, debtor);
        if (is_fully_repaid) {
            bottle::destroy_bottle(&mut bucket.bottle_table, debtor);
        };
        bucket.minted_buck_amount = bucket.minted_buck_amount - buck_input_amount;
        balance::split(&mut bucket.collateral_vault, return_amount)
    }

    public(friend) fun handle_repay_capped<T>(
        bucket: &mut Bucket<T>,
        debtor: address,
        buck_input_amount: u64,
        oracle: &BucketOracle,
        clock: &Clock,
    ): Balance<T> {
        assert!(bottle_exists<T>(bucket, debtor), EBottleNotFound);
        let (_, buck_amount) = bottle::get_bottle_info_after_update(&mut bucket.bottle_table, debtor);
        assert!(buck_amount >= buck_input_amount, ERepayTooMuch);
        let bottle = bottle::borrow_bottle_mut(&mut bucket.bottle_table, debtor);
        let (is_fully_repaid, return_amount) = bottle::record_repay_capped<T>(bottle, buck_input_amount, oracle, clock);
        bottle::update_stake_and_total_stake_by_debtor(&mut bucket.bottle_table, debtor);
        if (is_fully_repaid) {
            bottle::destroy_bottle(&mut bucket.bottle_table, debtor);
        };
        bucket.minted_buck_amount = bucket.minted_buck_amount - buck_input_amount;
        balance::split(&mut bucket.collateral_vault, return_amount)
    }

    public(friend) fun handle_redeem<T>(
        bucket: &mut Bucket<T>,
        oracle: &BucketOracle,
        clock: &Clock,
        buck_input_amount: u64,
        insertion_place: Option<address>,
    ): Balance<T> {
        let (price, denominator) = bucket_oracle::get_price<T>(oracle, clock);
        let collateral_output = balance::zero();
        let remaining = buck_input_amount;
        while(remaining > 0 && bottle::get_table_length(&bucket.bottle_table) > 0) {
            let debtor = option::destroy_some(bottle::get_lowest_cr_debtor(&bucket.bottle_table));
            let (_, bottle_buck_amount) = bottle::get_bottle_info_after_update(&mut bucket.bottle_table, debtor);
            // A fully-redeemed bottle has zero debt; there is nothing more to redeem,
            // so stop rather than re-selecting it forever.
            if (bottle_buck_amount == 0) break;
            let (debtor, bottle) = bottle::pop_front(&mut bucket.bottle_table);
            if (remaining >= bottle_buck_amount) {
                let redeemed_amount = compute_buck_value_to_collateral(bottle_buck_amount, bucket.collateral_decimal, price, denominator);
                bottle::record_redeem(&mut bottle, redeemed_amount, bottle_buck_amount);
                balance::join(&mut collateral_output, balance::split(&mut bucket.collateral_vault, redeemed_amount));
                bottle::push_back(&mut bucket.bottle_table, debtor, bottle);
                remaining = remaining - bottle_buck_amount;
            } else {
                let redeemed_amount = compute_buck_value_to_collateral(remaining, bucket.collateral_decimal, price, denominator);
                bottle::record_redeem(&mut bottle, redeemed_amount, remaining);
                balance::join(&mut collateral_output, balance::split(&mut bucket.collateral_vault, redeemed_amount));
                bottle::insert(&mut bucket.bottle_table, debtor, bottle, insertion_place);
                remaining = 0;
                break
            };
            // update the debtor's stakes
            bottle::update_stake_and_total_stake_by_debtor(&mut bucket.bottle_table, debtor);
        };
        assert!(remaining == 0, ENotEnoughToRedeem);
        bucket.minted_buck_amount = bucket.minted_buck_amount - buck_input_amount;

        collateral_output
    }

    public fun bottle_exists<T>(bucket: &Bucket<T>, debtor: address): bool {
        bottle::bottle_exists(&bucket.bottle_table, debtor)
    }

    public fun get_bottle_info<T>(bucket: &Bucket<T>, bottle: &Bottle): (u64, u64) {
        bottle::get_bottle_info(&bucket.bottle_table, bottle)
    }

    public fun get_bottle_info_by_debtor<T>(bucket: &Bucket<T>, debtor: address): (u64, u64) {
        bottle::get_bottle_info_by_debtor(&bucket.bottle_table, debtor)
    }

    public fun is_healthy_bottle<T>(bucket: &Bucket<T>, oracle: &BucketOracle, clock: &Clock, bottle: &Bottle): bool {
        let min_collateral_ratio = if (is_in_recovery_mode(bucket, oracle, clock)) {
            bucket.recovery_mode_threshold
        } else {
            bucket.min_collateral_ratio
        };
        let (price, denominator) = bucket_oracle::get_price<T>(oracle, clock);
        let (coll_amount, buck_amount) = get_bottle_info(bucket, bottle);
        compute_collateral_value_to_buck(coll_amount, bucket.collateral_decimal, price, denominator) >=
            mul_factor(buck_amount, min_collateral_ratio, 100)
    }

    public fun get_bucket_tcr<T>(bucket: &Bucket<T>, oracle: &BucketOracle, clock: &Clock): u64 {
        let collateral_amount = balance::value(&bucket.collateral_vault) + bucket.total_flash_loan_amount;
        let debt_amount = bucket.minted_buck_amount;
        let (price, denominator) = bucket_oracle::get_price<T>(oracle, clock);
        let coll_value = compute_collateral_value_to_buck(collateral_amount, bucket.collateral_decimal, price, denominator);
        mul_factor(coll_value, 100, debt_amount)
    }

    public fun get_bottle_icr<T>(bucket: &Bucket<T>, oracle: &BucketOracle, clock: &Clock, debtor: address): u64 {
        let (price, denominator) = bucket_oracle::get_price<T>(oracle, clock);
        let (coll_amount, buck_amount) = get_bottle_info_by_debtor(bucket, debtor);
        let coll_value = compute_collateral_value_to_buck(coll_amount, bucket.collateral_decimal, price, denominator);
        let coll_ratio = if (buck_amount > 0) {
            mul_factor(coll_value, 100, buck_amount)
        } else { // denominator cannot be 0, represent infinity ICR when debt is 0
            constants::max_u64()
        };
        coll_ratio
    }

    public fun get_bottle_table_length<T>(bucket: &Bucket<T>): u64 {
        bottle::get_table_length(&bucket.bottle_table)
    }

    public fun get_collateral_vault_balance<T>(bucket: &Bucket<T>): u64 {
        balance::value(&bucket.collateral_vault)
    }

    public fun get_minted_buck_amount<T>(bucket: &Bucket<T>): u64 {
        bucket.minted_buck_amount
    }

    public fun get_lowest_cr_debtor<T>(bucket: &Bucket<T>): Option<address> {
        bottle::get_lowest_cr_debtor(&bucket.bottle_table)
    }

    public fun is_liquidateable<T>(
        bucket: &Bucket<T>,
        oracle: &BucketOracle,
        clock: &Clock,
        debtor: address,
    ): bool {
        assert!(bottle_exists(bucket, debtor), EBottleNotFound);
        let bottle = bottle::borrow_bottle(&bucket.bottle_table, debtor);
        !is_healthy_bottle(bucket, oracle, clock, bottle)
    }

    public fun is_in_recovery_mode<T>(bucket: &Bucket<T>, oracle: &BucketOracle, clock: &Clock): bool {
        let (price, denominator) = bucket_oracle::get_price<T>(oracle, clock);
        let bucket_total_collateral_amount = balance::value(&bucket.collateral_vault) + bucket.total_flash_loan_amount;
        compute_collateral_value_to_buck(bucket_total_collateral_amount, bucket.collateral_decimal, price, denominator) <=
            mul_factor(bucket.minted_buck_amount, bucket.recovery_mode_threshold, 100)
    }

    public(friend) fun handle_flash_borrow<T>(
        bucket: &mut Bucket<T>,
        amount: u64,
    ): (Balance<T>, FlashReceipt<T>) {
        bucket.total_flash_loan_amount = bucket.total_flash_loan_amount + amount;
        let fee = amount / constants::flash_loan_fee_divisor();
        if (fee == 0) fee = 1;
        (balance::split(&mut bucket.collateral_vault, amount), FlashReceipt { amount, fee })
    }

    public(friend) fun handle_flash_repay<T>(
        bucket: &mut Bucket<T>,
        repayment: Balance<T>,
        recipit: FlashReceipt<T>,
    ): Balance<T> {
        let FlashReceipt { amount, fee } = recipit;
        bucket.total_flash_loan_amount = bucket.total_flash_loan_amount - amount;
        assert!(balance::value(&repayment) >= amount + fee, EFlashFeeNotEnough);
        let repayment_to_vault = balance::split(&mut repayment, amount);
        balance::join(&mut bucket.collateral_vault, repayment_to_vault);
        repayment
    }

    public fun is_not_locked<T>(bucket: &Bucket<T>): bool {
         bucket.total_flash_loan_amount == 0
    }

    public fun get_total_flash_loan_amount<T>(bucket: &Bucket<T>): u64 {
        bucket.total_flash_loan_amount
    }

    public fun get_flash_loan_info<T>(recipit: &FlashReceipt<T>): (u64, u64) {
        (recipit.amount, recipit.fee)
    }

    public fun get_minimum_collateral_ratio<T>(bucket: &Bucket<T>): u64 {
        bucket.min_collateral_ratio
    }

    public fun compute_base_rate_fee<T>(bucket: &Bucket<T>, current_time: u64): u64 {
        let minutes = (current_time - bucket.latest_redemption_time) / 60000;
        if (minutes > 525600000) minutes = 525600000;
        if (minutes == 0) return 5000;

        let y = constants::decay_factor_precision();
        let x = constants::minute_decay_factor();
        let n = minutes;

        while (n > 1) {
            if (n % 2 == 0) {
                x = mul_factor(x, x, constants::decay_factor_precision());
                n = n >> 1;
            } else {
                y = mul_factor(x ,y, constants::decay_factor_precision());
                x = mul_factor(x, x, constants::decay_factor_precision());
                n = (n - 1) / 2;
            };
        };

        let decay_factor = mul_factor(x, y, constants::decay_factor_precision());
        mul_factor(bucket.base_rate_fee, decay_factor, constants::decay_factor_precision())
    }

    fun compute_collateral_value_to_buck(collateral_amount: u64, collateral_decimal: u8, price: u64, denominator: u64): u64 {
        let collateral_raw_value = mul_factor(collateral_amount, price, denominator);
        if (constants::buck_decimal() >= collateral_decimal) {
            collateral_raw_value * math::pow(10, constants::buck_decimal() - collateral_decimal)
        } else {
            collateral_raw_value / math::pow(10, collateral_decimal - constants::buck_decimal())
        }
    }

    fun compute_buck_value_to_collateral(buck_amount: u64, collateral_decimal: u8, price: u64, denominator: u64, ): u64 {
        let buck_raw_value = mul_factor(buck_amount, denominator, price);
        if (constants::buck_decimal() >= collateral_decimal) {
            buck_raw_value / math::pow(10, constants::buck_decimal() - collateral_decimal)
        } else {
            buck_raw_value * math::pow(10, collateral_decimal - constants::buck_decimal())
        }
    }

    public(friend) fun update_base_rate_fee<T>(
        bucket: &mut Bucket<T>,
        base_rate_fee: u64,
        latest_redemption_time: u64
    ) {
        bucket.base_rate_fee = base_rate_fee;
        bucket.latest_redemption_time = latest_redemption_time;
    }

    public(friend) fun update_snapshot<T>(bucket: &mut Bucket<T>) {
        let collateral_vault_balanace = get_collateral_vault_balance(bucket);
        bottle::update_snapshot(&mut bucket.bottle_table, collateral_vault_balanace);
    }

    public(friend) fun handle_redistribution<T>(bucket: &mut Bucket<T>, debtor: address): (Balance<T>, Balance<T>) {
        let (collateral_amount, debt_amount) = get_bottle_info_by_debtor(bucket, debtor);
        let rebate_amount = mul_factor(collateral_amount, constants::liquidation_rebate(), constants::fee_precision());
        let rebate = balance::split(&mut bucket.collateral_vault, rebate_amount);
        let fee = balance::split(&mut bucket.collateral_vault, rebate_amount);
        collateral_amount = mul_factor(collateral_amount, constants::fee_precision() - 2*constants::liquidation_rebate(), constants::fee_precision());
        bottle::record_redistribution(&mut bucket.bottle_table, collateral_amount, debt_amount);
        bottle::destroy_bottle(&mut bucket.bottle_table, debtor);
        (fee, rebate)
    }

    #[test_only]
    use sui::sui::SUI;

    #[test_only]
    public fun check_bottle_order_in_bucket<T>(bucket: &Bucket<T>) {
        bottle::check_bottle_order_in_bucket(&bucket.bottle_table);
    }

    #[test]
    fun test_compute_base_rate_fee(): Bucket<SUI> {
        use sui::test_scenario;

        let dev = @0xde1;

        let scenario_val = test_scenario::begin(dev);
        let scenario = &mut scenario_val;

        let bucket = new<SUI>(110, 150, 9, test_scenario::ctx(scenario));
        bucket.base_rate_fee = 50000;

        std::debug::print(&bucket);
        std::debug::print(&compute_base_rate_fee(&bucket, 43200000 * 3));

        test_scenario::end(scenario_val);

        bucket
    }
}
