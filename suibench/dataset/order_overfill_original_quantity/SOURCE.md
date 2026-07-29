# order_overfill_original_quantity — Source provenance

Confirmed-tier entry (has `harness/`). Layer 2 (business logic), family: order-matching. A fill uses the
order's original quantity, not its remaining. **Confirmability: `confirmable-value`**
— a taker over-fills a stale order and drains the maker's funds (adversary = taker; victim = the maker).

## Provenance
- **provenance-tier: named-audit** (Critical)
- **disclosure-date: 2024–2025** (OtterSec DeepBook / margin-deepbook audit)
- **Source:** OtterSec — DeepBook, finding **OS-MDB-ADV-00**: `generate_fill` uses the maker order's original
  quantity, ignoring prior partial fills (and expiry), so a taker over-fills a stale order.
- **Class:** matched size computed from original order quantity rather than remaining (`quantity - filled`).

## Vulnerability
`take` computes `fill = min(take_qty, order.quantity)` — capping by the ORIGINAL quantity, never subtracting
`order.filled`. So a partially-filled (or fully-filled) order can be matched again up to its full original
size, and each fill splits base out of the maker's shared `Manager` balance. A taker over-fills a
nearly-exhausted order to drain the maker's account beyond what the order ever offered.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction: a maker `Manager` holding a `Balance<ASSET>` (a
  fixed-supply OTW coin so balance-delta checks are clean), an `Order` tracking `quantity`/`filled`, and a
  `take` that fills against `quantity` instead of `quantity - filled`. The quote side of the trade is elided
  to keep the model minimal — the labeled bug is the over-fill quantity on the base side.

## Decontamination
- Package/address `challenge`; module `orderbook`. No vuln/audit/fix-naming comments in `sources/` (the bug
  is the `order.quantity` cap in `take` ignoring `order.filled`). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
