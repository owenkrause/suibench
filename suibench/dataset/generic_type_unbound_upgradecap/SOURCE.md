# generic_type_unbound_upgradecap — Source provenance

Detect-tier entry (no `harness/`). Class 2 (abilities & types), sub-class: generic type param not bound
to the authorizing/stored value (type confusion).

## Provenance
- **provenance-tier: named-audit** (Critical)
- **disclosure-date: 2026-03-21**
- **Source:** Zellic — Matrixdock XAGm assessment, finding **3.1 "The UpgradeCap can be stolen"**
  (Critical, fix `d9bc2f84`), target `mtoken.move`, fn `revoke_transfer_ownership<T>`.
- **Class:** type confusion / broken authorization — a function generic over `T` authorizes against a
  caller-supplied `State<T>` that is never bound to the escrowed request, so an attacker's own state
  passes the owner check.
- Provenance twist worth noting: the sibling XAUm audit (2025-07-28) reviewed the same generic pattern
  and reported no critical, claiming it was safe; the 2026 XAGm audit found this Critical.

## Vulnerability
`revoke_transfer_ownership<T>(state: &State<T>, req: TransferOwnershipReq, ...)` checks
`state.owner == sender` but the `req` (which escrows the real `sui::package::UpgradeCap`) carries no
binding to the `State<T>` it was created against. `create_state<T>` is permissionless, so an attacker
creates a `State<Fake>` they own, passes it with a victim's `TransferOwnershipReq`, passes the owner
check against their own state, and the escrowed `UpgradeCap` is `public_transfer`'d to them.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** The Matrixdock source repo is private, so this is a faithful minimal reconstruction of
  the mechanism Zellic quotes: a phantom-typed `State<T>`, a `TransferOwnershipReq` escrowing a real
  `sui::package::UpgradeCap`, a `check_owner` gate, and the vulnerable `revoke_transfer_ownership<T>`
  whose `State<T>` argument is not bound to the request. Uses the real `UpgradeCap` type for faithfulness
  (the module only needs to compile and contain the vulnerable logic — no cap is minted).

## Decontamination
- Package/address `challenge`; module `mtoken`. No vuln/audit/fix/protocol-naming comments in `sources/`
  (the bug is the unbound generic in the function signature, visible in code). Edition `2024`. Builds
  clean with `sui move build --build-env mainnet` (one non-fatal `non-composable transfer to sender` lint).
