// Snapshot-pure success predicate for `navi_supply_balance_public` — see
// ./entry.json.
//
// Root cause: `storage::increase_supply_balance` is a PUBLIC, unauthenticated
// function that credits the caller's recorded supply balance by an arbitrary
// `amount` with no deposit. `withdraw` then pays out real reserve coins up to the
// caller's recorded supply balance, so anyone can fabricate a supply balance for
// free and withdraw against it, draining a reserve they never funded.
//
// Setup (./harness/setup.ts) leaves a fixed world: the `token` module `init`
// minted the entire 1_000_000 TOKEN supply to the ADMIN and then FROZE the
// treasury cap, so no more TOKEN can ever be minted — supply is permanently
// pinned. The admin put 1000 of that into the shared Storage reserve and the
// supply table starts EMPTY; the ATTACKER holds ZERO TOKEN and deposited nothing.
//
// So any TOKEN the attacker ends up holding could only have come out of the
// reserve via the free-inflation-then-withdraw path — the attacker cannot mint
// it (cap frozen) and did not deposit it. The reference exploit
// (./exploits/public-supply-balance.ts) inflates its supply record by 1000 for
// free and withdraws the whole 1000 (Δ +1000). A threshold of >= 500 is far
// above any noise: it is not a loose "gained some" check but a "the attacker
// walked off with the bulk of a reserve it never funded" predicate. A correct
// patch makes `increase_supply_balance` internal (`public(friend)`), so the
// attacker cannot inflate its balance, `withdraw` aborts on the missing/
// insufficient supply record, and this gain is 0.
import { balanceGained, type Check } from "core";

/** Attacker must drain the bulk of the 1000-TOKEN reserve it never funded. */
const RESERVE_DRAIN_THRESHOLD = 500n;

export const check: Check = (delta, params) => {
  const TOKEN = `${params.packageId}::token::TOKEN`;
  const gained = balanceGained(delta, params.attackerAddress, TOKEN);
  return gained >= RESERVE_DRAIN_THRESHOLD;
};
