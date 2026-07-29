module challenge::constants {
    // Constant
    const LIQUIDATION_REBATE: u64 = 2500; // 0.25%

    const FEE_PRECISION: u64 = 1000000;
    const MINIMAL_BOTTLE_SIZE: u64 = 500000000000; // 500 BUCK
    const FLASH_LOAN_FEE_DIVISOR: u64 = 10000; // 0.01% fee
    const MINUTE_DECAY_FACTOR: u64 = 999037758833783500;
    const DECAY_FACTOR_PRECISION: u64 = 1000000000000000000;
    const BUCK_DECIMAL: u8 = 9;
    const MAX_U64: u64 = 0xffffffffffffffff;
    const P_INITIAL_VALUE: u64 = 1000000000000000000;
    const SCALE_FACTOR: u64 = 1000000000; // 1e9
    const MAX_LOCK_TIME: u64 = 31104000000; // ms of 360 days
    const MIN_LOCK_TIME: u64 = 2592000000; // ms of 30 days
    const MIN_FEE: u64 = 5000; // 0.5%
    const MAX_FEE: u64 = 50000; // 5%

    // TODO: token allocation, recipient address and vesting
    const BKT_TOTAL_SUPPLY: u64 = 100000000000; // supply: 100M
    const FOR_ALLOCATION: u64 = 40000000000; // 40%
    const FOR_TANK_CONTRIBUTORS: u64 = 60000000000; // 60%

    public fun fee_precision(): u64 { FEE_PRECISION }

    public fun liquidation_rebate(): u64 { LIQUIDATION_REBATE }

    public fun minimal_bottle_size(): u64 { MINIMAL_BOTTLE_SIZE }

    public fun flash_loan_fee_divisor(): u64 { FLASH_LOAN_FEE_DIVISOR }

    public fun minute_decay_factor(): u64 { MINUTE_DECAY_FACTOR }

    public fun decay_factor_precision(): u64 { DECAY_FACTOR_PRECISION }

    public fun buck_decimal(): u8 { BUCK_DECIMAL }

    public fun max_u64(): u64 { MAX_U64 }

    public fun p_initial_value(): u64 { P_INITIAL_VALUE }

    public fun scale_factor(): u64 { SCALE_FACTOR }

    public fun max_lock_time(): u64 { MAX_LOCK_TIME }

    public fun min_lock_time(): u64 { MIN_LOCK_TIME }

    public fun min_fee(): u64 { MIN_FEE }

    public fun max_fee(): u64 { MAX_FEE }

    public fun bkt_total_supply(): u64 { BKT_TOTAL_SUPPLY }

    public fun for_allocation(): u64 { FOR_ALLOCATION }

    public fun for_tank_contributors(): u64 { FOR_TANK_CONTRIBUTORS }

}
