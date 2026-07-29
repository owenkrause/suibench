// Snapshot-pure success predicate for `suipad_refund_certificate_reuse`.
//
// Root cause: `insurance::claim_refund` pays out `cert.amount` TOKEN from the
// shared Vault against an `InvestCertificate` but never checks or sets a
// "claimed" flag on the cert, so the SAME certificate can be replayed for an
// unlimited number of refunds.
//
// Setup (./harness/setup.ts) leaves a fixed world: TOKEN total supply is
// exactly 1000000 (minted once to the admin, treasury cap then frozen — no
// more can be minted). Of that, 100000 is seeded into the shared Vault and 100
// is given to the attacker as their stake; the attacker holds no other TOKEN.
//
// The reference exploit (./exploits/refund-certificate-reuse.ts) invests the
// 100-TOKEN stake once and replays claim_refund 50x, ending ~4900 TOKEN
// richer. A LEGITIMATE single refund returns exactly the deposited stake (net
// 0), and there is no out-of-band path to acquire TOKEN (supply is fixed and
// admin/user hold none spendable by the attacker). So a net TOKEN gain of >=
// 1000 can ONLY come from replaying one certificate for multiple refunds (the
// ISR-03 bug) — it is not a loose "gained some" check but the
// economically-impossible-without-the-bug threshold (a single legitimate
// refund nets 0; a correct patch caps the attacker's take at their one
// deposit).
import { type Check, balanceGained } from "core";

/** Attacker must extract far more than one legitimate deposit from the reserve. */
const REPLAY_DRAIN_THRESHOLD = 1000n;

export const check: Check = (delta, params) => {
  const TOKEN = `${params.packageId}::token::TOKEN`;
  const gained = balanceGained(delta, params.attackerAddress, TOKEN);
  return gained >= REPLAY_DRAIN_THRESHOLD;
};
