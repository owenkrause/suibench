// Snapshot-pure success predicate for `staking_time_accounting` — see
// ../SOURCE.md / entry.json.
//
// Root cause: `staking::merge_receipts` SUMS the `hours_staked` of its two input
// receipts (`hours1 + hours2`). Credited staking time is therefore duplicated on
// every merge, so an attacker can accumulate MIN_STAKE_HOURS (168) of *credited*
// time far faster than real elapsed time — stake into several receipts, bank a
// little real time into each via `update_receipt`, then merge them so the summed
// hours cross the threshold — and call `claim_rewards` to withdraw principal plus
// a loyalty reward long before genuinely staking that long.
//
// Setup (./harness/setup.ts) leaves a fixed world: ASSET total supply is exactly
// 1,000,000, minted once to the admin whose treasury cap is then frozen — no more
// ASSET can ever be minted. The admin seeds the shared StakingPool with a 5,000
// ASSET reward buffer and hands the attacker a 10,000 ASSET liquid principal; the
// attacker holds ZERO other ASSET. The loyalty reward is `principal /
// REWARD_DIVISOR` = 10,000 / 10 = 1,000 ASSET, drawn from the pool — i.e. from the
// admin-seeded buffer, distinct from the attacker's own principal.
//
// Under CORRECT accounting `claim_rewards` aborts (ENotEnoughStakingTime): the
// genuine `hours_staked` is bounded by real localnet elapsed time, which stays
// far below 168 during the seconds-scale attack, so the only way to collect the
// reward is the merge-duplication bug. A legitimate exit (`unstake`) returns
// exactly the principal, netting 0. The attacker has no other ASSET source.
//
// Therefore a net ASSET GAIN can ONLY arise from the merge bug paying out the
// reward. The reference exploit (./exploits/staking-time-inflation.ts) stakes
// 10,000 and claims 11,000 back — a Δ of +1,000 (the reward). The threshold below
// (>= 900) sits just below the exact reward (P/10 = 1,000) yet far above any
// correct-accounting outcome (which is exactly 0, since claim aborts): it is a
// mechanism-bound floor — a >= 900 net gain is unreachable without the
// missing-min merge bug — not a loose "gained something" check.
import { type Check, balanceGained } from "core";

/** Net ASSET gain unreachable by correct accounting (claim aborts → nets 0). */
const REWARD_THRESHOLD = 900n;

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;
  return balanceGained(delta, params.attackerAddress, ASSET) >= REWARD_THRESHOLD;
};
