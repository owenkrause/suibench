# liquidation_seize_uncapped — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: lending / liquidation. Collateral
seizure not capped by debt repaid. **Confirmability: `confirmable-value`** — a liquidator repays dust and
seizes the whole collateral (adversary = liquidator; victim = the borrower).

## Provenance
- **provenance-tier: named-audit** (High)
- **disclosure-date: 2024–2025** (OtterSec NAVI audit)
- **Source:** OtterSec — NAVI, finding **OS-NVI-ADV-02** (unfair liquidation): `calculate_max_liquidation`
  never caps max-collateral by max-debt, so a liquidator repays a tiny debt yet seizes large collateral.
- **Class:** liquidation seizure amount not bounded by the repayment amount.

## Vulnerability
`liquidate` confirms the loan is underwater and reduces `debt` by the repayment, but seizes
`balance::value(&loan.collateral)` — the entire collateral — with no cap tied to `repay`. A liquidator
repays a dust amount and takes all of the borrower's collateral, clearing only a sliver of the debt.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction of the reported bug: a `liquidate` that reduces debt by
  the repayment but computes the collateral seizure without a `min(collateral, repay * bonus)` cap.

## Decontamination
- Package/address `challenge`; module `lending`. No vuln/audit/fix-naming comments in `sources/` (the bug is
  `seize = balance::value(&loan.collateral)` with no dependence on `repay`). Edition `2024`. Builds clean
  with `sui move build --build-env mainnet`.
