# negative_fee_collateral_inflation — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: fee accrual — a signed-fee sign check
omitted. **Confirmability: `confirmable-value`** — the attacker inflates collateral and withdraws real SUI
(adversary = the account holder; victim = other depositors / the exchange vault).

## Provenance
- **provenance-tier: real-incident** (on-chain exploit, Critical)
- **disclosure-date: 2026** (Aftermath perpetuals exploit, ~$1.14M; analysis by DARKNAVY)
- **Source:** Aftermath Finance perpetuals — negative integrator-fee exploit. The fee was upper-bounded but
  not lower-bounded, so a negative signed fee turned `value - fee` into `value + |fee|`, inflating account
  collateral.
- **Class:** signed-arithmetic sign-error in fee application (Layer-2 accounting logic).

## Vulnerability
`settle_fee` validates only `fee.magnitude <= MAX_FEE`, never that the fee is non-negative. A fee should be
subtracted from collateral, but the `negative` branch adds it. An attacker submits `Fee { negative: true }`,
gets their collateral credited for free, and withdraws the fabricated balance — draining the shared vault.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction of the documented incident mechanism: a caller-supplied
  signed fee (`{ magnitude, negative }`), a `settle_fee` that bounds only the magnitude, and an `Account` /
  `Exchange` vault so the inflated collateral converts to a real SUI withdrawal. (The real Aftermath code
  uses a custom `I64`-style signed integer; this models the same missing-non-negativity check with a minimal
  signed representation.)

## Decontamination
- Package/address `challenge`; module `perp`. No vuln/incident/fix-naming comments in `sources/` (the bug is
  the missing sign check in `settle_fee` + the `+` in the negative branch). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
