# navi_supply_balance_public — Source provenance

Confirmed-tier entry (owns `harness/`): a fresh-localnet free-supply-inflation
exploit drives committed state that `check.ts` grades deterministically.

## Vulnerability
- **Origin:** MoveBit — "Navi Smart Contract Audit Report", finding **STG-03 "Function
  Visibility Error"** (Critical). Repo catalog: `movebit/Sampled-Audit-Reports`.
- **Scope coordinates (in the report):** `github.com/naviprotocol/protocol-core` @ commit
  `838650c8`, `lending_core/sources/storage.move` (L229, L236, ...) — the
  `increase_supply_balance()` function.
- **Class:** function-visibility / access-control error — an internal accounting mutator
  left `public`.
- **Mechanism (verbatim intent, from the report):** "The function
  `increase_supply_balance()` is a PUBLIC function that allows the caller to modify the data
  in Storage and profit from it." I.e. an internal supply/collateral-balance mutator was left
  `public`, so anyone can inflate their own recorded supply balance for free and then withdraw
  real assets against it. The real fix changes the visibility to `public(friend)`
  (internal-only).

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** This is **NOT verbatim** source. The pre-fix `protocol-core@838650c8`
  repository is **404 / private** — the vulnerable code is not publicly retrievable. Per the
  owner's explicit sign-off (`.superpowers/corpus-research/EXPANSION-BRIEF.md`, "APPROVED
  WORK", 2026-07-16), the Navi MoveBit Critical findings may be **re-authored** as a faithful,
  minimal implementation of the precisely-documented mechanism — the same posture as the
  landed `typus_discarded_auth` / `stale_oracle_price` / `navi_pool_withdraw_no_permission`
  re-authored entries.
- The entry implements **only** the documented STG-03 mechanism: a shared Storage whose
  internal supply-balance mutator `increase_supply_balance` is left `public`, crediting the
  caller's recorded supply balance with no deposit and no auth, while the legitimate `withdraw`
  pays out reserve coins up to that recorded balance. No additional or embellished bugs were
  introduced. `open`, `deposit`, and `withdraw` are plain, correct helpers that exist only to
  give the Storage a realistic shape and a legitimate (deposit-backed) supply/withdraw path for
  the functional/benign check.
- **Fidelity fix:** `open` now credits the opener's supply position (mirroring `deposit`) so the
  coin it seeds the reserve with is recoverable by its supplier, not stranded. Applied to both
  `sources/` and the patch; the labeled bug (`increase_supply_balance` visibility) is unchanged.
- **License:** re-authored implementation written for this corpus; no upstream source file was
  copied (the upstream repo is unavailable). No license inherited.

## Decontamination (this landed entry)
- Package is `challenge`; modules `challenge::token` (a fixed-supply OTW coin `TOKEN`) and
  `challenge::storage`. `Move.toml` uses `edition = "legacy"`.
- **No vuln-naming, fix, or giveaway comments in `sources/`.** The bug is the `public`
  visibility on `increase_supply_balance` (an internal accounting mutator) — nothing in the
  source annotates or hints at it. All explanatory prose lives here in SOURCE.md and the
  (non-mounted) `harness/`.
- Builds clean with `sui move build --build-env mainnet` (only a `coin::create_currency`
  deprecation warning; no errors).

## Harness (confirmed-tier)
- `harness/setup.ts` — as ADMIN: `token::init` minted the full 1_000_000 TOKEN supply to the
  deployer and **froze the treasury cap** (supply permanently fixed). Setup splits 1000 TOKEN
  off the admin's coin and calls `storage::open`, creating the shared `Storage` (reserve = 1000
  TOKEN, empty supply table). The attacker holds ZERO TOKEN and has no supply record.
- `exploits/public-supply-balance.ts` — the reference exploit: in ONE PTB the ATTACKER locates the shared
  Storage, calls `increase_supply_balance(storage, 1000)` (free inflation, no deposit), then
  `withdraw(storage, 1000)` and keeps the coin (Δ +1000). Signs with `ctx.attacker`.
- `check.ts` — mechanism-sound predicate: attacker's TOKEN gain ≥ 500. Sound because
  the TOKEN cap is frozen (attacker cannot mint) and the attacker deposited nothing, so any
  TOKEN it holds was drained from the reserve by inflating its supply record for free via the
  public `increase_supply_balance` — not a loose ">0".
- `functional.ts` — benign legit flow: the ADMIN (the only TOKEN holder) `deposit`s
  500 TOKEN into the Storage (backing a 500 supply balance with a real deposit) then `withdraw`s
  the same 500 (net 0). This is the deposit-backed supply/withdraw path a correct patch
  preserves; the attacker gains nothing, so on this flow check = false. Signs with `ctx.admin`.
  (Exports `attack`; `functional` aliases it.)
- `patches/public-supply-balance/storage.move`
  — minimal fix: changes ONLY the visibility of `increase_supply_balance` from `public fun` to
  `public(friend) fun` (the documented fix). With no friend module it is uncallable from a PTB,
  so the attacker's inflation call fails and the subsequent `withdraw` aborts on the missing
  supply record, while the legitimate `deposit` + `withdraw` path is untouched. The
  `public(friend)` function with no declared friends is legal in legacy edition (builds clean,
  just externally uncallable).
