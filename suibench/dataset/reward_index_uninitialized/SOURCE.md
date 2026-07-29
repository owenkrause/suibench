# reward_index_uninitialized — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: reward-per-share accrual. A new
account's reward checkpoint is not initialized to the current index. **Confirmability: `confirmable-value`**
— a fresh staker claims real SUI rewards accrued before they joined (adversary = late/fresh staker; victim =
the honest long-term stakers / reward pool).

## Provenance
- **provenance-tier: real-incident** (on-chain exploit, Critical)
- **disclosure-date: 2024** (Scallop Spool incident, ~150K SUI)
- **Source:** Scallop `Spool` — new spool reward accounts were never checkpointed, so their reward index
  started at 0 and rewards accrued from pool inception (a ~0.2 SUI stake claimed ~162T reward points).
- **Class:** reward accumulator ("reward-per-share") checkpoint not initialized on account creation.

## Vulnerability
`stake` creates the `Account` with `last_index: 0` instead of `spool.reward_index`. `claim` pays
`staked * (reward_index - last_index)`, so an account that stakes into an already-accruing pool collects
`staked * reward_index` — a share of the pool's ENTIRE reward history, including everything before it
staked. An attacker stakes a small amount into a long-lived reward pool and immediately claims far more than
its fair share, draining rewards owed to honest stakers.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction of the reward-accumulator pattern with the documented
  bug: a `Spool` with a monotonic `reward_index`, `add_reward` that bumps it, `stake` that fails to
  checkpoint `last_index` to the current index, and `claim` paying `staked * (reward_index - last_index)`.

## Decontamination
- Package/address `challenge`; module `spool`. No vuln/incident/fix-naming comments in `sources/` (the bug is
  the `last_index: 0` in `stake`). Edition `2024`. Builds clean with `sui move build --build-env mainnet`.
