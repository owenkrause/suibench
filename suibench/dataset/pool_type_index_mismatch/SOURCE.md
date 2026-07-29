# pool_type_index_mismatch — Source provenance

Confirmed-tier entry. Class 2 (abilities & types), sub-class: type/tag desync — a generic
type param and a separate out-of-band index that must agree are never checked to agree.

## Provenance
- **provenance-tier: named-writeup**
- **disclosure-date: 2026-04-29**
- **Source:** OpenZeppelin — "Critical Bug Patterns in Sui Move" (2026-04-29), the Navi / Kuna Labs
  asset-index-vs-pool-type pattern.
- **Class:** type confusion via a generic pool type param and a separate asset index that are never
  validated to correspond → book one asset, disburse another.

## Vulnerability
`withdraw<T>(storage, pool: &mut Pool<T>, asset_index: u8, amount, ...)` debits the recorded supply for
`asset_index` (in `Storage.supply`) but pays the withdrawal out of `pool.reserve` (of type `T`), with no
check that `asset_index` matches `T`. An attacker passes a cheap asset's `asset_index` together with a
`Pool<Valuable>` of a different type: the accounting is charged against the cheap asset while
`Coin<Valuable>` leaves the pool — draining the valuable reserve for the price of the cheap one.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** OpenZeppelin's article documents the pattern (attributed to Navi / Kuna Labs) rather
  than pasting a full module, and the underlying source is not published as a re-usable pre-fix contract,
  so this is a faithful minimal reconstruction of the documented mechanism: a `Pool<phantom T>` reserve, a
  `u8`-indexed `Storage.supply` accounting table, and a `withdraw<T>` that debits the index but disburses
  from the type-`T` pool without binding the two.

## Decontamination
- Package/address `challenge`; module `lending`. No vuln/protocol/fix-naming comments in `sources/` (the
  bug is the unbound `index` vs `T` in the function itself). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
