module challenge::error {

    public fun new_address_can_not_be_same_as_current_one(): u64 { 1 }
    public fun object_version_mismatch(): u64 { 2 }
    public fun transaction_replay(): u64 { 3 }
    public fun invalid_guardian(): u64 { 4 }
    public fun invalid_deleveraging_operator(): u64 { 5 }
    public fun invalid_funding_rate_operator(): u64 { 6 }
    public fun invalid_settlement_operator(): u64 { 7 }
    public fun not_a_public_settlement_cap(): u64 { 8 }
    public fun operator_already_removed(): u64 { 9 }

    public fun min_price_greater_than_zero(): u64 { 20 }
    public fun min_price_less_than_max_price(): u64 { 21 }
    public fun max_price_greater_than_min_price(): u64 { 22 }
    public fun step_size_greater_than_zero(): u64 { 23 }
    public fun tick_size_greater_than_zero(): u64 { 24 }
    public fun mtb_long_greater_than_zero(): u64 { 25 }
    public fun mtb_short_greater_than_zero(): u64 { 26 }
    public fun mtb_short_less_than_hundred_percent(): u64 { 27 }
    public fun max_limit_qty_greater_than_min_qty(): u64 { 28 }
    public fun max_market_qty_less_than_min_qty(): u64 { 29 }
    public fun min_qty_less_than_max_qty(): u64 { 30 }
    public fun min_qty_greater_than_zero(): u64 { 31 }
    public fun trade_price_less_than_min_price(): u64 { 32 }
    public fun trade_price_greater_than_max_price(): u64 { 33 }
    public fun trade_price_tick_size_not_allowed(): u64 { 34 }
    public fun trade_qty_less_than_min_qty(): u64 { 35 }
    public fun trade_qty_greater_than_limit_qty(): u64 { 36 }
    public fun trade_qty_greater_than_market_qty(): u64 { 37 }
    public fun trade_qty_step_size_not_allowed(): u64 { 38 }
    public fun trade_price_greater_than_mtb_long(): u64 { 39 }
    public fun trade_price_greater_than_mtb_short(): u64 { 40 }

    public fun oi_open_greater_than_max_allowed(_is_taker: u64): u64 { 41 }
}
