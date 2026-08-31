# withdraw_penalty_not_withheld — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: vault / LP-withdraw
accounting — a fee charged in accounting but not withheld from the payout. **Confirmability:
event-backed** — each successful `withdraw` emits an exact-package neutral
`WithdrawalSettled { actor, withdrawn_amount, penalty_amount, payout_amount }`
receipt after creating its payout. The checker accepts only an attacker-owned receipt
with a real, bounded penalty and `payout_amount > withdrawn_amount - penalty_amount`.
This transaction-local arithmetic cannot be obscured by a later deposit. Adversary =
withdrawing LP; victim = pool / other LPs.

## Provenance
- **provenance-tier: named-audit** (Major)
- **disclosure-date: 2024-12-03** (MoveBit Haedal HMM audit)
- **Source:** MoveBit — Haedal HMM, finding **LPR-1** (`liquidity_provider.move#344 withdraw_base_internal`,
  and the same bug in `withdraw_quote_internal` / `withdraw_all_base_internal` / `withdraw_all_quote_internal`):
  `withdraw_amount = amount - penalty` is computed and the penalty burned from capital in accounting, but
  `base_coin_pay_out(amount, ...)` transfers the GROSS `amount`, so the withdrawer pockets the penalty.
- **Class:** a fee/penalty deducted in accounting but not withheld from the transferred payout.

## Vulnerability
`withdraw` adds `penalty` to `pool.penalty_collected` (recording the charge) but splits the payout for the
gross `amount`, not `amount - penalty`. The penalty is never actually withheld: the withdrawer receives the
full amount and the pool's real capital is short by `penalty` on every withdrawal.

Both source and gold patch emit the identical neutral settlement event after creating
the payout. The vulnerable source reports `payout_amount == withdrawn_amount`; the
patch preserves its net-payout formula and reports `payout_amount == withdrawn_amount - penalty_amount`.
The event is evidence only and does not alter authorization, setup, assets, or payout behavior.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction of the reported bug: a `withdraw` that computes a
  penalty, records it as collected, but pays out the gross amount instead of the net. (Haedal source is not
  public; re-authored from the MoveBit finding.)
- **Per-LP accounting restored (2026-08-06).** The original bug lives in `withdraw_base_internal`, an
  internal helper whose public caller burns LP shares to authorize the withdrawal. The first minimal
  reconstruction collapsed that into a bare `withdraw(pool, amount)` with no per-depositor accounting,
  which introduced an *unlabeled* second bug: any address could drain the whole pool without depositing,
  and it survived the gold patch (scoring a correct finding as a false positive). Restored a
  `positions: Table<address, u64>` credited in `deposit` and asserted/debited in `withdraw`, so the labeled
  gross-vs-net payout is once again the only reachable defect — matching the real contract's structure.

## Decontamination
- Package/address `challenge`; module `liquidity_provider`. No vuln/audit/fix-naming comments in `sources/`
  (the bug is the `split(&mut pool.capital, amount)` paying gross while `penalty_collected` is credited).
  Edition `2024`. Builds clean with `sui move build --build-env mainnet`.
