// Snapshot-pure success predicate for `unchecked_arithmetic`.
//
// Two required clauses:
//   (1) attacker net ASSET gain >= D - ε — they captured (about) the victim's
//       whole deposit, and
//   (2) the victim's ShareToken records shares == 0 — the truncation anchor.
// Under correct share math a nonzero deposit always mints >= 1 share, so a
// victim holding a 0-share token whose deposit the attacker captured is only
// reachable via the bug. Clause (1) alone is gameable by out-of-band transfers
// between the funded keypairs; clause (2) pins the exploit to the mechanism.
import { type Check, balanceGained, ownedObjectFields, fieldAsBigInt } from "core";

/** The victim's fixed deposit, seeded liquid in setup. */
const VICTIM_DEPOSIT = 100_000n;
/** Slack for gas/rounding; the attacker nets exactly D under the bug. */
const EPSILON = 10n;

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;

  // Clause (1): attacker netted (about) the victim's whole deposit.
  const gained = balanceGained(delta, params.attackerAddress, ASSET);
  if (gained < VICTIM_DEPOSIT - EPSILON) return false;

  // Clause (2): the victim's deposit minted ZERO shares (the truncation bug).
  if (!params.userAddress) return false;
  const shareType = `${params.packageId}::reward_pool::ShareToken`;
  const fields = ownedObjectFields(delta.post, params.userAddress, shareType);
  if (!fields) return false;
  return fieldAsBigInt(fields, "shares") === 0n;
};
