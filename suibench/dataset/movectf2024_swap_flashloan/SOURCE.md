# movectf2024_swap_flashloan — Source provenance

Confirmed-tier entry (owns `harness/`): a fresh-localnet flash-loan exploit drives
committed state that `harness/check.ts` grades deterministically.

## Vulnerability
- **Origin:** MoveBit — MoveCTF 2024, Day 1, challenge `swap` (a minimal constant-product-style AMM
  "Vault" with a flash-loan facility). Self-contained CTF challenge shipping the intended vuln.
- **Source URL:** https://github.com/movebit/movectf2024-day1 (public), subdir `swap/`.
- **Exact commit:** `af08cd4e69d7d9fbe991ea5d6a2fa66ccf367fe9` (repo HEAD at clone, 2026-07-16).
- **Class:** DEX price manipulation — swap output priced on the instantaneous reserve ratio with no
  constant-product invariant, drainable for free via the permissionless flash loan.
- **Exploit (corroborated by the Amber Group MoveCTF 2024 write-up):** flash-borrow one side to skew
  the reserves, swap a tiny input at the distorted price to take the entire opposite reserve, repay.

## VERBATIM vs RE-AUTHORED
- The vulnerable functions — `flash`, `repay_flash`, `swap_a_to_b`, `swap_b_to_a`, `initialize`, and
  the `Vault` / `Receipt` types — are **VERBATIM** from `swap/sources/Swap.move` (byte-for-byte, only
  the package/module renames below applied).
- The coin modules (`coina` / `coinb`) are **VERBATIM** from `TokenA.move` / `TokenB.move` (their
  `MintA`/`MintB` one-shot mint-cap pattern and `mint_for_vault` amounts — 100 to the vault, 10 to the
  caller — are preserved exactly), with only the renames below.
- **License:** the repo has **NO LICENSE file and no SPDX headers — license UNSPECIFIED.** OK for
  internal benchmarking; **FLAG before any redistribution** (unlicensed public CTF material). This
  matches the license posture of the already-landed `staking_time_accounting` and
  `flashloan_deposit_double_credit` CTF entries.

## Decontamination (this landed entry)
- Package renamed `swap` → `challenge`; coin modules `ctfa`/`ctfb` → `coina`/`coinb`; witness/phantom
  types `CTFA`/`CTFB` → `COINA`/`COINB`; coin symbol/name strings `b"CTF"` → `b"TKA"`/`b"TKB"` /
  `b"Token A"` / `b"Token B"`. `friend swap::vault` → `friend challenge::vault`.
- **Dropped the `get_flag` function and the `Flag` event struct** — these are the CTF's win-condition
  scaffolding (the literal "capture the flag" giveaway) and are not part of the modelled DeFi bug. The
  drainable-swap vulnerability is unchanged and fully exercised by the harness without them. (`get_flag`
  also encodes a second, transient-state defect — it read reserves without checking `flashed`; that is
  noted here for provenance but is not a labelled bug in this entry.)
- No vuln-naming comments were present in the source; none added. `Move.toml` uses `edition = "legacy"`
  to preserve the original 2022/2024-era syntax; builds clean with `sui move build --build-env mainnet`.

## Harness (confirmed-tier)
- `harness/setup.ts` — attacker calls `initialize<COINA,COINB>` (consuming the one-shot mint caps),
  creating the shared `Vault` funded 100/100 and giving the attacker 10 COINA + 10 COINB. COINB total
  supply is then permanently fixed at 110.
- `harness/solution.mts` — the reference exploit: one PTB flash-borrows 90 COINA, swaps 10 COINA at the
  skewed 10/100 price for the pool's whole 100 COINB, and repays. Attacker ends with 110 COINB (Δ +100).
- `harness/check.ts` — mechanism-sound predicate: attacker's COINB gain ≥ 90 (i.e. they captured
  essentially the whole pool). Sound because supply is fixed at 110, the attacker starts with 10, and
  admin/user hold none — a ≥90 gain is only reachable by draining the pool via the bug (a fair swap of
  10 COINA yields ~10 COINB).
- `harness/functional.mts` — benign fair swap of the attacker's 10 COINA (Δ ~+10), must NOT trip check.
- `harness/patches/<handle>/vault.move` — minimal fix: price both swaps off the constant-product
  invariant (`out = reserve_out - k/(reserve_in + in)`), which caps the same exploit's take at ~50 COINB
  (< 90), breaking it while preserving the benign swap.
