module challenge::vesting {
    use sui::bcs::{Self, BCS};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::clock::Clock;

    /// A merkle-vesting allocation, committed as raw serialized bytes at creation
    /// and decoded lazily at withdrawal time.
    public struct Vesting has key {
        id: UID,
        funds: Balance<SUI>,
        beneficiary: address,
        allocation: vector<u8>,
    }

    /// One linear vesting interval decoded from the committed allocation.
    public struct Piece has drop {
        start_time: u32,
        period_length: u32,
        number_of_periods: u32,
        amount: u64,
    }

    /// Commit an allocation (raw serialized bytes) alongside the vested funds.
    /// The bytes are decoded lazily at withdrawal time.
    public fun create(funds: Coin<SUI>, beneficiary: address, allocation: vector<u8>, ctx: &mut TxContext) {
        transfer::share_object(Vesting {
            id: object::new(ctx),
            funds: coin::into_balance(funds),
            beneficiary,
            allocation,
        });
    }

    fun deserialize_piece(stream: &mut BCS): Piece {
        Piece {
            start_time: stream.peel_u32(),
            period_length: stream.peel_u32(),
            number_of_periods: stream.peel_u32(),
            amount: stream.peel_u64(),
        }
    }

    fun calc_vested_piece_amount(piece: &Piece, final_timestamp: u32): u64 {
        // FIX: guard the deserialized divisors. A zero period_length or
        // number_of_periods is a degenerate schedule (nothing to vest per period),
        // so nothing has vested yet — return 0 instead of dividing by zero. This
        // keeps a poisoned allocation from permanently bricking withdraw.
        if (piece.period_length == 0 || piece.number_of_periods == 0) {
            return 0
        };
        let elapsed_time = final_timestamp - piece.start_time;
        let fully_vested_periods = elapsed_time / piece.period_length;
        piece.amount * (fully_vested_periods as u64) / (piece.number_of_periods as u64)
    }

    public fun withdraw(vesting: &mut Vesting, clock: &Clock, ctx: &mut TxContext): Coin<SUI> {
        assert!(ctx.sender() == vesting.beneficiary, 0);
        let bytes = vesting.allocation;
        let mut stream = bcs::new(bytes);
        let piece = deserialize_piece(&mut stream);
        let final_timestamp = ((clock.timestamp_ms() / 1000) as u32);
        let vested = calc_vested_piece_amount(&piece, final_timestamp);
        coin::take(&mut vesting.funds, vested, ctx)
    }
}
