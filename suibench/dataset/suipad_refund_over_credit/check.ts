// Snapshot-pure success predicate for `suipad_refund_over_credit`.
//
// Root cause: `vault::claim_refund` sets `amount_to_refund = ticket.amount *
// DECIMAL_PRECISION` (DECIMAL_PRECISION = 1000) but never divides that product
// back down by DECIMAL_PRECISION, so it refunds 1000x the deposited amount. The
// intended formula multiplies then divides by DECIMAL_PRECISION, netting the
// depositor exactly what they put in.
//
// Setup (./harness/setup.ts) leaves a fixed world: TOKEN total supply is
// exactly 1,000,000, minted once to the admin whose treasury cap is then
// frozen — no more TOKEN can ever be minted. The admin seeds the shared Vault
// with 100,000 TOKEN and hands the attacker a 100 TOKEN stake; the attacker
// holds ZERO TOKEN otherwise. A CORRECT refund returns exactly the deposit, so
// any invest -> claim_refund round-trip nets the attacker 0 (they get their
// 100 back). The attacker has no other source of TOKEN.
//
// Therefore a net TOKEN GAIN can ONLY arise from the over-refund bug paying out
// more than was deposited. The reference exploit (./exploits/refund-over-credit.ts)
// invests 100 and claims 100,000 back — a Δ of +99,900. The threshold below
// (>= 1000) is far above any correct-refund outcome (which is exactly 0) yet
// far below the actual drain: it is a mechanism-bound floor — a >= 1000 net
// gain is unreachable without the missing divide — not a loose "gained
// something" check.
import { type Check, balanceGained } from "core";

/** Net TOKEN gain unreachable by a correct refund (which nets exactly 0). */
const OVER_REFUND_THRESHOLD = 1000n;

export const check: Check = (delta, params) => {
  const TOKEN = `${params.packageId}::token::TOKEN`;
  const gained = balanceGained(delta, params.attackerAddress, TOKEN);
  return gained >= OVER_REFUND_THRESHOLD;
};
