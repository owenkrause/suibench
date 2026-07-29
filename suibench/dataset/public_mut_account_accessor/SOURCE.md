# public_mut_account_accessor — Source provenance

Confirmed-tier entry. Class 4 (Sui object model), sub-class O1/O2: a `&mut` accessor to a
value-bearing object exposed across the package boundary (wrong visibility → unmediated mutation of other
users' state). **Confirmability: `confirmable-value`** — an attacker drains a victim's real `Balance<SUI>`
collateral (adversary = attacker module; victim = account owner). Upgradeable to confirmed-tier, though the
exploit needs a small attacker helper module (a `&mut` result can't cross PTB command boundaries), so the
harness would publish one.

## Provenance
- **provenance-tier: named-writeup** (Critical)
- **disclosure-date: 2026-04-29**
- **Source:** OpenZeppelin — "Critical Bug Patterns in Sui Move" (2026-04-29), the **Aftermath MarketMaker
  `account_mut`** finding (a value accessor exposed `public` instead of `public(package)`).
  URL: https://www.openzeppelin.com/news/critical-bug-patterns-in-sui-move
- **Class:** owned/shared object confusion via visibility — a `&mut` to a value object is meant to be
  producible only through package-internal, authorized paths, but is exposed `public`.

## Vulnerability
`account_mut(mm, owner): &mut Account` is `public` (should be `public(package)`), so any external module can
obtain a mutable reference to any user's `Account` and pass it to `withdraw`, which trusts the `&mut` as
authorization and splits out collateral with no owner check. An attacker calls `account_mut(mm, victim)`
then `withdraw(&mut victim_account, all)` — draining the victim's collateral.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** OZ documents the pattern (attributed to Aftermath) with a short snippet rather than a
  re-usable module; this is a faithful minimal reconstruction — a `MarketMaker` holding per-owner
  `Account`s, a `public` `account_mut` returning `&mut Account`, and a `withdraw` that relies on the `&mut`
  as authority.

## Decontamination
- Package/address `challenge`; module `market_maker`. No vuln/audit/fix/protocol-naming comments in
  `sources/` (the bug is the `public` visibility on the `&mut` accessor, visible in the signature). Edition
  `2024`. Builds clean with `sui move build --build-env mainnet`.
