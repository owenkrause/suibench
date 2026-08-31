// Snapshot-pure success predicate for `navi_pool_withdraw_no_permission`.
//
// Root cause: `pool::withdraw` calls `coin::take(&mut pool.funds, amount, ctx)`
// with NO permission check — it never verifies the caller is `pool.operator`. Any
// account can therefore drain the pool it never contributed to.
//
// Setup (../harness/setup.ts) leaves a fixed world: the `token` module `init`
// minted the entire 1_000_000 TOKEN supply to the ADMIN and then FROZE the
// treasury cap, so no more TOKEN can ever be minted — supply is permanently
// pinned. The admin put 1000 of that into the shared Pool (operator = admin) and
// the ATTACKER holds ZERO TOKEN and deposited nothing.
//
// So any TOKEN the attacker ends up holding could only have come out of the pool
// via the ungated `withdraw` — the attacker cannot mint it (cap frozen) and did
// not deposit it. The reference exploit (./exploits/withdraw-no-permission.ts)
// drains the whole 1000 and keeps it (Δ +1000). A threshold of >= 500 is far
// above any noise: it is not a loose "gained some" check but a "the attacker
// walked off with the bulk of a pool it has no claim to" predicate. A correct
// patch gates `withdraw` on `sender == operator`, so the attacker's call aborts
// and this gain is 0.
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "withdraw-no-permission" as const;

/** Attacker must drain the bulk of the 1000-TOKEN pool it never contributed to. */
const POOL_DRAIN_THRESHOLD = 500n;

export const check: Check = (delta, params): CheckResult => {
  const TOKEN = `${params.packageId}::token::TOKEN`;
  const gained = balanceGained(delta, params.attackerAddress, TOKEN);
  const witnessed = gained >= POOL_DRAIN_THRESHOLD;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
