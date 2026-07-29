# withdraw_residual_not_debited — Source provenance

Detect-tier entry (no `harness/`). Layer 2 (business logic), family: deposit/withdraw accounting — a residual
that leaves the pool is not debited from user state. **Confirmability: `confirmable-value`** — the attacker
accumulates a phantom balance and withdraws it as real SUI (adversary = a withdrawing user; victim = the
vault / other depositors).

## Provenance
- **provenance-tier: named-audit** (High, triple-corroborated: Veridise VUL-003 / OtterSec OS-NVP-ADV-01)
- **disclosure-date: 2024–2025** (NAVI audits)
- **Source:** NAVI — VUL-003 / OS-NVP-ADV-01: a residual (< 1000, from a precision conversion) is sent to the
  treasury on withdraw without decrementing the user's recorded state, double-counting the residual.
- **Class:** value that leaves the pool on the user's behalf is not charged against the user's balance.

## Vulnerability
`withdraw` moves `RESIDUAL_FEE` from `funds` to `treasury` but decrements the caller's recorded balance only
by `amount` (not `amount + RESIDUAL_FEE`). The residual is thus spent from the pool yet still counted in the
user's claim, leaving a phantom balance that accumulates over repeated withdrawals and is eventually
withdrawn as real SUI — draining the vault at the expense of other depositors.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction: a `withdraw` that splits a residual to the treasury but
  debits user state only by the withdrawn amount. (The real NAVI residual is a precision-conversion remainder;
  modeled here as a small fixed residual, which produces the same "residual not debited" double-count.)

## Decontamination
- Package/address `challenge`; module `vault`. No vuln/audit/fix-naming comments in `sources/` (the bug is the
  residual leaving `funds` while `*bal` is decremented only by `amount`). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
