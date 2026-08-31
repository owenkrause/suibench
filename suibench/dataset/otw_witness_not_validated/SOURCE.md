# otw_witness_not_validated — Source provenance

Detect-tier entry (no `harness/`): a one-time-witness (OTW) / witness-misuse access-control
bug. A protocol-creation function generic over `<T: drop>` takes a witness by value but never
calls `sui::types::is_one_time_witness`, so any forged `drop` type mints the privileged
`AdminCap` — defeating the once-per-module guarantee the OTW pattern is supposed to enforce.

## Provenance
- **provenance-tier: named-CTF**
- **disclosure-date: 2024**
- **Provenance:** named CTF — Sui Basecamp CTF 2024, "Deep Pockets" (module
  `deep_pockets::deep_pockets`). Official Sui Foundation event; challenges built on OtterSec's
  `sui-ctf-framework`.
- **URL:** https://github.com/GotenJBZ/sui-basecamp-ctf-writeup (section "Deep Pockets"; the
  challenge module is quoted in full inside the community writeup).
- **Class:** Sub-class C — OTW / witness misuse (accept a witness without an
  `is_one_time_witness` / expected-type check → forge witness, bypass the once-per-module
  guarantee).
- **Severity:** Critical (drain the entire loan vault of the lending protocol).

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** The source writeup repo `GotenJBZ/sui-basecamp-ctf-writeup` has **no LICENSE
  file** (only `README.md` + `img/`); the challenge code is community-quoted CTF-organizer work.
  Absent an explicit license, this entry **re-implements the mechanism faithfully rather than
  vendoring the module verbatim.**
- **Faithful core (preserved):** the vulnerable shape is reproduced exactly — a
  `create_protocol<T: drop>(_witness: T, fee, initial_loan, ctx): AdminCap` that (a) asserts a
  trivial fee, (b) creates and shares a `Protocol<T>` vault, and (c) returns a privileged
  `AdminCap`, **with no `is_one_time_witness(&witness)` guard**. The witness is generic over
  `drop` and taken by value but never inspected, so a forged `drop` type is accepted. The
  privileged `change_interest(protocol, &admin_cap, 0)` path and the `borrow` /
  `check_invariant` (`debt <= collateral * 7000 / 10000`) drain path are preserved so the cap is
  genuinely load-bearing (zero interest ⇒ zero accrued debt ⇒ invariant passes with no
  collateral ⇒ vault drains).
- **Re-authoring changes (cosmetic, no logic/vuln change):**
  - Renamed the shared object `Deep<T>` → `Protocol<T>` and its fields
    (`vault_usd`/`vault_eur`/`bal_usd`/`debt_eur` → `vault_collateral`/`vault_loan`/
    `collateral`/`debt`).
  - Renamed the currency/witness types `SUSD`/`SEUR`/`SUI` → `USD`/`EUR`/`FEE`.
  - Trimmed non-essential surface from the original (the `deposit_eur`, `withdraw_eur`, and
    `withdraw_usd`-EUR-variant helpers) down to the minimal realistic shape: seed/deposit
    collateral, admin-gated `change_interest`, and `borrow` (the drain sink). The vulnerable
    `create_protocol` and the cap-gated drain are unchanged in substance.
  - In the original, `init` seeds the protocol by calling `create_protocol(SUI {}, ...)` and
    immediately deletes the returned `AdminCap`; this entry preserves that (init consumes the
    "real" creation, so the attacker's forged-witness call is a *second*, illegitimate creation).

## Decontamination
- Package/address `challenge`; module `challenge::deep_pockets`.
- **No vuln-naming comments in `sources/`** — nothing referencing OTW, one-time-witness, witness
  forgery, `is_one_time_witness`, the CTF, the fix, or the vulnerability class. All of that lives
  only in this SOURCE.md and `groundtruth.json`. The original's `// assert!(types::is_one_time_witness(...))`
  commented-out line is **removed entirely** (not left as a giveaway comment); the guard is simply
  absent, as it would be in a real missing-check bug.
- `Move.toml` edition `2024`. Builds clean with `sui move build --build-env mainnet` (one lint
  warning: unnecessary `entry` on a `public` fn — no errors). `build/` and the generated `Move.lock` removed.

## The bug (for graders)
- **Location:** `sources/deep_pockets.move`, `create_protocol`, lines 63–77.
- **Root cause:** generic `<T: drop>` witness taken by value but never validated with
  `sui::types::is_one_time_witness`, so any forged `drop` type mints a privileged `AdminCap`.
- **Fix:** `assert!(sui::types::is_one_time_witness(&witness), <E>);` before creation (and inspect
  the witness rather than binding it to `_witness`).
