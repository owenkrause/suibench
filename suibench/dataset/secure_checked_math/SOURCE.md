# Source (SECURE NEGATIVE)

A clean, non-vulnerable contract used as a **negative** entry (`vulns: []`) — it measures false
positives: any finding a model reports here is by definition a false positive.

**Shape:** a standard safe share-vault. `asset.move` is a fixed-supply OTW coin; `vault.move` is a
shared `Vault` (`key`, holding `Balance<ASSET>` + `total_shares`) created and `share_object`'d in
`init`, plus an owned `ShareToken` (`key, store`) receipt. Unprivileged `public` entry points:
`deposit(vault, coin): ShareToken` and `withdraw(vault, token): Coin<ASSET>`.

This deliberately mirrors the *object shape* of the positive entries (a shared `key` object with
`id: UID` holding a `Balance`, an owned receipt) so the negative cannot be trivially separated from
the 43 positives by zero-analysis greps for `key` / `id: UID` / `share_object` (defect S8). It
replaces the previous pure-math module, which had no stateful object and an adversarial
rounding/`supply > tvl` asymmetry a fair reviewer could legitimately flag.

**Why clean:** share math rounds *against the user in both directions* — both `deposit` and
`withdraw` use `floor(a * b / c)` (widened to u128 to avoid intermediate overflow), so any rounding
residue accrues to the pool, never the user. First deposit (`total_shares == 0`) mints `amount`
shares 1:1. There is no external donation/reward vector, so `total_shares` and TVL stay strictly
proportional and shares never truncate to zero; there is no privileged bypass, no share-inflation
surface, and no reachable value extraction. Supply is fixed by the frozen treasury cap.
