module challenge::auction {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::clock::Clock;
    use challenge::asset::ASSET;

    public struct Auction has key {
        id: UID,
        seller: address,
        end_time_ms: u64,
        highest_bid: u64,
        highest_bidder: address,
        balance: Balance<ASSET>,
        settled: bool,
    }

    public struct BidReceipt has key, store {
        id: UID,
        auction_id: ID,
        bidder: address,
        amount: u64,
    }

    public fun create_auction(
        end_time_ms: u64,
        ctx: &mut TxContext,
    ) {
        transfer::share_object(Auction {
            id: object::new(ctx),
            seller: ctx.sender(),
            end_time_ms,
            highest_bid: 0,
            highest_bidder: @0x0,
            balance: balance::zero(),
            settled: false,
        });
    }

    public fun bid(
        auction: &mut Auction,
        payment: Coin<ASSET>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        assert!(!auction.settled, 0);
        assert!(clock.timestamp_ms() < auction.end_time_ms, 1);

        let bid_amount = coin::value(&payment);
        assert!(bid_amount > auction.highest_bid, 2);

        // Refund the previous highest bidder by handing them a receipt they can
        // cash with `claim_refund`.
        if (auction.highest_bid > 0) {
            transfer::public_transfer(
                BidReceipt {
                    id: object::new(ctx),
                    auction_id: object::id(auction),
                    bidder: auction.highest_bidder,
                    amount: auction.highest_bid,
                },
                auction.highest_bidder,
            );
        };

        balance::join(&mut auction.balance, coin::into_balance(payment));
        auction.highest_bid = bid_amount;
        auction.highest_bidder = ctx.sender();
    }

    public fun settle(
        auction: &mut Auction,
        ctx: &mut TxContext,
    ) {
        assert!(!auction.settled, 4);

        auction.settled = true;

        let total = balance::value(&auction.balance);
        let payment = coin::take(&mut auction.balance, total, ctx);
        transfer::public_transfer(payment, auction.seller);
    }

    public fun claim_refund(
        auction: &mut Auction,
        receipt: BidReceipt,
        ctx: &mut TxContext,
    ): Coin<ASSET> {
        let BidReceipt { id, auction_id, bidder: _, amount } = receipt;
        object::delete(id);
        assert!(object::id(auction) == auction_id, 5);
        coin::take(&mut auction.balance, amount, ctx)
    }
}
