# flashloan_receipt_droppable — Source provenance

Confirmed-tier entry. Class 3 (resource / hot-potato), sub-class R2: a hot potato wrongly
given the `drop` ability, defeating its enforced-consumption guarantee.

## Provenance
- **provenance-tier: checklist / audit-pattern** (documented real audit finding, protocol not named)
- **disclosure-date: ~2025** (documented in multiple 2025 Sui-security writeups)
- **Source:** the canonical Move hot-potato safety bug, documented as a real audit finding across
  Trail of Bits (2025-09-10), Mirage Audits / Pushkar Mishra "The Ability Mistakes That Will Drain Your
  Sui Move Protocol" (`FlashLoanReceipt has drop` → pool drained), OpenZeppelin, and the MoveBit
  "Sui Objects Security Principles" blog. URL:
  https://medium.com/@pushkarm029/the-ability-mistakes-that-will-drain-your-sui-move-protocol-1a2c317e373f
- **Provenance note:** this is a **pattern-tier** entry — the sources describe it as a bug caught in a
  real audit, but no single named protocol/finding-ID is public (the closest named instance, the Zellic
  "Billion Dollar Move Bug", is a Move *bytecode-verifier* defect, not a re-authorable contract). It is
  included despite the weaker provenance because it is *the* canonical Move hot-potato safety property,
  it models cleanly, and no existing corpus entry tests it (contrast the class-2 store-leak-theft, which
  was held for being both weakly-sourced AND fuzzy AND overlapping).

## Vulnerability
`FlashLoanReceipt` is declared `has drop`. The flash-loan invariant depends on the receipt being a true
hot potato (no abilities), so that the only way to discharge it is `repay_flash_loan`. With `drop`, the
borrower calls `flash_loan`, keeps the coin, and lets the receipt be dropped — no repayment, no compiler
error, pool drained.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED** from the documented pattern (a minimal flash-loan `Pool` with a `flash_loan` /
  `repay_flash_loan` pair whose `FlashLoanReceipt` carries the erroneous `drop` ability).

## Decontamination
- Package/address `challenge`; module `pool`. No vuln/fix-naming comments in `sources/` (the bug is the
  `has drop` on the receipt struct, visible in code). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
