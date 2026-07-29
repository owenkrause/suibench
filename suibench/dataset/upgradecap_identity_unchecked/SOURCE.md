# upgradecap_identity_unchecked — Source provenance

Confirmed-tier entry. Class 2 (abilities & types), sub-class: authorizing capability's
identity not validated (a real framework cap accepted as proof without checking *which* thing it governs).

## Provenance
- **provenance-tier: real-incident** (Critical, disclosed exploit)
- **disclosure-date: 2026-01-28**
- **Source:** Pawtato Finance incident, via OpenZeppelin "Notorious Bug Digest #8". An entry function
  accepted a framework `&UpgradeCap` as authorization but never checked which package it belonged to, so
  any attacker's own `UpgradeCap` minted a privileged cap.
- **Class:** broken authorization — gating on possession of a universally-obtainable framework object
  (`UpgradeCap`) without validating its identity.

## Vulnerability
`claim_admin(_upgrade_cap: &UpgradeCap, ...)` mints an `AdminCap` to anyone who presents any `UpgradeCap`.
Because every published package yields its own `UpgradeCap` to its publisher, an attacker publishes a
throwaway package, gets a valid `UpgradeCap`, and passes it to `claim_admin` to mint admin authority —
then drains the shared `Treasury` through the admin-gated `withdraw`. The missing check is
`package::upgrade_package(cap) == <this package's id>`.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** The Pawtato source is not published as a re-usable pre-fix module, so this is a faithful
  minimal reconstruction of the documented mechanism: a `claim_admin` that accepts a real
  `sui::package::UpgradeCap` as authorization but never validates its identity, plus an admin-gated
  treasury withdrawal to give the escalation concrete impact.

## Decontamination
- Package/address `challenge`; module `admin`. No vuln/incident/fix-naming comments in `sources/` (the bug
  is the accepted-but-unvalidated cap in the function signature/body). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet` (one non-fatal lint).

## Note
Distinct from `capability_leak` (mints a cap with no gate at all) and `otw_witness_not_validated` (forged
one-time witness): here the gate *looks* real (you must present a framework `UpgradeCap`) but authorizes
nothing because that object is obtainable by everyone — a false-sense-of-authorization bug.
