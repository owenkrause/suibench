# shared_object_race — Source

Confirmed-tier entry (has `harness/`). Authored for this repo as an
intentionally-vulnerable test contract: a simple auction over a fixed-supply
`ASSET` coin with a shared `Auction` object and `bid` / `settle` / `claim_refund`
entry points.

Vuln: `settle` transfers the ENTIRE `auction.balance` to the seller instead of
only the winning bid (`highest_bid`). The balance also holds outbid bidders'
refundable deposits — when a higher bid arrives, `bid` hands the previous highest
bidder a `BidReceipt` refundable for their amount and leaves that amount in the
balance. Because `settle` sweeps everything to the seller, an outbid bidder's
later `claim_refund` aborts against an empty balance: their deposit is stolen.

Adversary = a seller who shill-bids one unit over a victim to outbid them, then
settles, receiving the victim's deposit on top of their own returned shill bid
(net gain = the victim's stranded deposit). Victim = the outbid bidder whose
refund can no longer be honored.

Note: the entry name references a "race", but the exploitable, committed-state
harm is single-tx/sequential (the over-sweep of an outbid deposit), independent
of any concurrency — that is what the harness confirms. The fix pays the seller
only `highest_bid`, leaving outbid deposits claimable via `claim_refund`.

## Decontamination
- Package/address `challenge`; modules `auction` + `asset`. No vuln/fix-naming
  comments in `sources/`. Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
