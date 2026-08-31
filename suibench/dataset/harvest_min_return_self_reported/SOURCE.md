# harvest_min_return_self_reported — Source provenance

Confirmed-tier entry. Class 3 (resource / hot-potato), sub-class R3: a hot-potato-mediated
operation whose safety invariant is checked against a self-reported value / a resettable snapshot rather
than real state. **Confirmability: `confirmable-value`** — an operator drains real pooled `Balance<ASSET>`
from depositors, an adversary-vs-victim theft with observable committed state (upgradeable to confirmed-tier).

## Provenance
- **provenance-tier: named-lab**
- **disclosure-date: 2024/2025** (Monethic Sui Move security workshop material)
- **Source:** Monethic `sui-vuln-lab`, lab `hot_potato`, module `vuln_lab::hot_potato_vault`.
  - Code: https://github.com/Monethic/sui-vuln-lab/blob/main/vulnlab/sources/hot_potato/hot_potato.move
  - Writeup: https://medium.com/@monethic/sui-move-security-workshop-writeup-material-480c5e7d1da3
- **Class:** a `HarvestOp` hot potato correctly forces `finish_harvest` to run, but the min-return check it
  enforces is defeatable — it trusts a caller-supplied `returned_amount` — so
  the operator can drain depositors past the floor that is supposed to protect them.

## Vulnerability
`finish_harvest(vault, op, returned_amount, ...)` asserts `returned_amount >= principal * 98%`, but
`returned_amount` is an operator-supplied `u64` never tied to an actual repaid coin or the vault's real
`balance::value(&funds)`. The operator does `start_harvest` → `withdraw_for_strategy` (pull the whole
`Coin<ASSET>` balance to themselves) → `finish_harvest(returned_amount = principal)`: the fabricated
number passes and the operator keeps all depositor funds. **Adversary = the strategy operator; victim = the depositors.**

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED, and deliberately RE-MODELED to expose the adversarial impact.** The `Monethic/sui-vuln-lab`
  repo has no LICENSE, so this re-implements the lab's logic faithfully. The lab used a *mock* `reserves: u64`
  counter and an admin-owned vault with no depositors — which makes the exploit look like an operator
  rugging their own vault (a footgun with no victim). This entry keeps the exact bug (min-return checked
  against a self-reported `returned_amount`) but restores the real-world structure the
  lab abstracts away: a shared vault holding real pooled depositor `Balance<ASSET>`, and `withdraw_for_strategy`
  handing the operator a real `Coin<ASSET>`. That makes it a genuine operator-vs-depositor theft rather than a
  self-inflicted loss.
- **Persistent floor restored (2026-08-06).** The first reconstruction snapshotted the floor per-call
  (`saved_reserves` at each `start_harvest`), which let a *compliant* operator repeat 2%-skim harvests and
  compound them to drain the vault — an unlabeled bug that survived the gold patch (a false positive). The
  floor is now anchored to a persistent `principal` high-water mark set on `deposit`, so the labeled
  self-reported-amount defect is the only reachable one. Applied to both `sources/` and the gold patch.

## Decontamination
- Package/address `challenge`; module `strategy_vault` (renamed from `hot_potato_vault`). Removed the lab's
  giveaway comments — especially the commented-out `//let current = vault.reserves;` line revealing the
  intended (correct) check. The vulnerable logic is unchanged. Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
