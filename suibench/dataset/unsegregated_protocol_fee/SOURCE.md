# unsegregated_protocol_fee — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: fee accrual — protocol fees not
segregated from LP-claimable reserves. **Confirmability: `confirmable-value`** — an LP redeems more than
they deposited, skimming real fee revenue (adversary = a liquidity provider; victim = the protocol / other
LPs whose fee share is diluted).

## Provenance
- **provenance-tier: named-audit** (Major)
- **disclosure-date: 2023–2024** (MoveBit MovEx audit)
- **Source:** MoveBit — MovEx finding **POL-11** (`pool.move#L84`, github.com/MoveExchange/MovEX-swap-v2):
  the unsegregated protocol fee sits in pool reserves and is captured by the next LP add/remove action.
- **Class:** protocol fees held in the same balance LPs redeem against, with LP redemption not excluding them.

## Vulnerability
`add_liquidity` mints LP shares against `reserve - protocol_fee` (correct), but `remove_liquidity` pays
`lp_amount * reserve / total_lp` against the FULL reserve, which still contains `protocol_fee`. The
asymmetry lets an LP redeem more than they deposited, skimming the protocol's fee revenue — a just-in-time
liquidity deposit right before fees accrue captures a share of them.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction: a pool holding a `protocol_fee` inside `reserve`, an
  `add_liquidity` that excludes it from the mint basis, and a `remove_liquidity` that fails to exclude it
  from the redeem basis. (Public `MoveExchange/MovEX-swap-v2` source could support a verbatim upgrade later.)

## Decontamination
- Package/address `challenge`; module `amm_pool`. No vuln/audit/fix-naming comments in `sources/` (the bug is
  the full-`reserve` basis in `remove_liquidity` vs the fee-excluded basis in `add_liquidity`). Edition
  `2024`. Builds clean with `sui move build --build-env mainnet`.
