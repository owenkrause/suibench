# flashloan_receipt_wrong_order — Source provenance

Confirmed-tier entry. Class 3 (resource / hot-potato), sub-class R1: hot-potato receipt not
bound to its source object.

## Provenance
- **provenance-tier: named-audit** (Critical)
- **disclosure-date: 2026-04-29**
- **Source:** OpenZeppelin — "Critical Bug Patterns in Sui Move" (2026-04-29), the **Cetus Limit Order**
  flash-loan repay-to-wrong-object finding (corroborated by Trail of Bits).
  URL: https://www.openzeppelin.com/news/critical-bug-patterns-in-sui-move
- **Class:** the canonical hot-potato R1 bug — a `FlashLoanReceipt` (no abilities, must be consumed same-tx)
  records its origin object's id, but the repay function never checks the receipt matches the object it is
  repaying into, so the loan is settled against the wrong order.

## Vulnerability
`flash_loan` stamps `order_id: object::id(order)` into the `FlashLoanReceipt`, but `repay_flash_loan`
destructures `order_id: _` (discards it) and only asserts the repaid amount — never that
`receipt.order_id == object::id(order)`. An attacker flash-borrows from a victim's `LimitOrder`, then
repays into their own order: the amount check passes, the borrowed funds land in the attacker's order, and
the victim's order is drained. The receipt enforces *that* and *how much* is repaid, but not *where*.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** The Cetus Limit Order source is not published as a re-usable pre-fix module; this is a
  faithful minimal reconstruction of the documented mechanism (a hot-potato `FlashLoanReceipt` carrying an
  `order_id` that `repay_flash_loan` ignores). The vulnerable pattern — receipt origin recorded but not
  verified at settlement — is reproduced exactly.

## Decontamination
- Package/address `challenge`; module `limit_order`. No vuln/audit/fix/protocol-naming comments in
  `sources/` (the bug is the discarded `order_id: _` and the absent id assertion, visible in code). Edition
  `2024`. Builds clean with `sui move build --build-env mainnet`.
