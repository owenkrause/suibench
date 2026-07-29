# bad_debt_no_writeoff — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: lending share/exchange-rate accounting.
Bad debt is never written off, so the share price stays inflated. **Confirmability: `confirmable-value`** —
an early redeemer extracts real liquidity at an overstated rate at the expense of late redeemers (adversary
= a default-watching early redeemer; victim = the honest cToken holders who redeem last).

## Provenance
- **provenance-tier: named-audit** (High)
- **disclosure-date: 2024** (Zellic Suilend assessment)
- **Source:** Zellic — Suilend, finding **3.1** (no bad-debt write-off). Insolvent debt keeps accruing/
  counting as a live asset, so the cToken exchange rate is overstated; early redeemers exit whole and the
  last redeemer eats the shortfall (bank run). Source repo `solendprotocol/suilend` is public.
- **Class:** uncollectable debt not written off the exchange rate → first-mover redeem advantage (bank run).

## Vulnerability
`redeem` prices cTokens by `backing / total_ctokens` with `backing = liquidity + total_debt`, but
`record_default` only increments a `defaulted` counter and never reduces `total_debt`. So the rate keeps
counting bad debt as an asset. Because the shortfall isn't socialized, whoever redeems first gets full value
from real liquidity; the last redeemer is stranded with cTokens backed only by the bad debt.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction of the reported mechanism: a cToken pool whose
  exchange-rate `backing` includes `total_debt`, a `record_default` that tracks but does not write off bad
  debt, and a `redeem` that pays the inflated rate first-come. (Public `solendprotocol/suilend` source could
  support a verbatim upgrade later.)

## Decontamination
- Package/address `challenge`; module `lending_pool`. No vuln/audit/fix-naming comments in `sources/` (the
  bug is that `record_default` never reduces `total_debt`, which `redeem` still counts). Edition `2024`.
  Builds clean with `sui move build --build-env mainnet`.
