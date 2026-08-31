module math_lib::math_u256 {
    const MASK_U128: u256 = 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff;
    const MASK_U64: u256  = 0x000000000000000000000000000000000000000000000000ffffffffffffffff;

    public fun div_mod(num: u256, denom: u256): (u256, u256) {
        let p = num / denom;
        let r: u256 = num - (p * denom);
        (p, r)
    }

    public fun shl_64(n: u256): u256 {
        n << 64
    }

    public fun shr_64(n: u256): u256 {
        n >> 64
    }

    public fun checked_shl_64(n: u256): (u256, bool) {
        let mask = 1 << 192;
        if (n >= mask) {
            (0, true)
        } else {
            ((n << 64), false)
        }
    }

    public fun div_round(num: u256, denom: u256, round_up: bool): u256 {
        let p = num / denom;
        if (round_up && ((p * denom) != num)) {
            p + 1
        } else {
            p
        }
    }
}
