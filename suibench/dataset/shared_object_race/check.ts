// Snapshot-pure success predicate for `shared_object_race`.
//
// Two required clauses:
//   (1) the attacker (the colluding seller) netted (about) the victim's whole
//       deposit V in ASSET, and
//   (2) the victim still owns a `BidReceipt` whose refundable `amount` equals
//       that captured gain — the anchor.
// A BidReceipt is only constructible inside `challenge::auction` and is handed
// out only on the `bid` outbid path, so clause (2) proves the attacker really
// ran the auction and outbid the victim; clause (1) alone is gameable by an
// out-of-band ASSET transfer between the funded keypairs. Under the patch,
// `settle` pays the seller only `highest_bid`, so the seller nets 0 (they are
// the highest bidder and get back exactly their shill) and clause (1) is false
// even though the victim still holds an honorable receipt.
import { type Check, type CheckResult, balanceGained, ownedObjects, fieldAsBigInt } from "core";

const LABEL_ID = "settle-strands-refunds" as const;

/** The victim's fixed deposit V, seeded live in the auction balance by setup. */
const VICTIM_DEPOSIT = 1_000n;
/** Slack for rounding; the attacker nets exactly V (ASSET, gas is paid in SUI). */
const EPSILON = 10n;

function absDiff(a: bigint, b: bigint): bigint {
  return a >= b ? a - b : b - a;
}

export const check: Check = (delta, params): CheckResult => {
  const ASSET = `${params.packageId}::asset::ASSET`;

  // Clause (1): the attacker/seller netted (about) the victim's whole deposit V.
  const gained = balanceGained(delta, params.attackerAddress, ASSET);
  if (gained < VICTIM_DEPOSIT - EPSILON) return { witnesses: [] };

  // Clause (2): the outbid victim still holds a receipt for exactly the swept
  // deposit — the refund they can no longer draw.
  if (!params.userAddress) return { witnesses: [] };
  const receipts = ownedObjects(
    delta.post,
    params.userAddress,
    `${params.packageId}::auction::BidReceipt`,
  );
  const witnessed = receipts.some((r) => {
    const amount = fieldAsBigInt(r.fields, "amount");
    return (
      amount !== null &&
      amount >= VICTIM_DEPOSIT - EPSILON &&
      absDiff(amount, gained) <= EPSILON
    );
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
