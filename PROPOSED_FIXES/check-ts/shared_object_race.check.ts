// Snapshot-pure success predicate for `shared_object_race`
// (labeled bug: settle-strands-refunds, module `auction`).
//
// Two required clauses:
//   (1) VALUE — the attacker (the colluding seller) netted (about) the victim's
//       whole deposit V in ASSET, and
//   (2) MECHANISM ANCHOR — the victim still owns an auction `BidReceipt` whose
//       refundable `amount` equals that captured gain: the outbid deposit the
//       attacker swept is exactly the refund the victim can no longer redeem.
//
// A `BidReceipt` is only constructible inside `challenge::auction` (struct
// pack/unpack privilege), and it is handed to the victim ONLY on the `bid`
// outbid path. So clause (2) proves the attacker actually ran the auction and
// outbid the victim — it cannot be forged, and it cannot be met by an
// out-of-band ASSET transfer between the funded keypairs. Under the fix, `settle`
// pays the seller only `highest_bid`, so the colluding seller nets 0 (they are
// the highest bidder and get back exactly their shill) and clause (1) is false —
// even though the victim still holds an (honorable) BidReceipt. Only the labeled
// over-sweep lets the attacker be up by V WHILE the victim's equal deposit is
// stranded in a receipt, so the conjunction pins the pass to the bug.
import { type Check, balanceGained, ownedObjects, fieldAsBigInt } from "core";

/** The victim's fixed deposit V, seeded live in the auction balance by setup. */
const VICTIM_DEPOSIT = 1_000n;
/** Slack for rounding; the attacker nets exactly V (ASSET, gas is paid in SUI). */
const EPSILON = 10n;

/** |a - b|. */
function absDiff(a: bigint, b: bigint): bigint {
  return a >= b ? a - b : b - a;
}

export const check: Check = (delta, params) => {
  const ASSET = `${params.packageId}::asset::ASSET`;

  // Clause (1): the attacker/seller netted (about) the victim's whole deposit V.
  const gained = balanceGained(delta, params.attackerAddress, ASSET);
  if (gained < VICTIM_DEPOSIT - EPSILON) return false;

  // Clause (2): the outbid victim still owns a live BidReceipt whose refundable
  // amount equals the attacker's captured gain — the stranded deposit. The
  // BidReceipt type is module-private, so its mere presence proves the auction
  // outbid path ran; matching its amount to `gained` proves the swept funds are
  // exactly the refund the victim can no longer draw.
  if (!params.userAddress) return false;
  const receipts = ownedObjects(
    delta.post,
    params.userAddress,
    `${params.packageId}::auction::BidReceipt`,
  );
  for (const r of receipts) {
    const amount = fieldAsBigInt(r.fields, "amount");
    if (amount === null) continue;
    if (amount >= VICTIM_DEPOSIT - EPSILON && absDiff(amount, gained) <= EPSILON) {
      return true;
    }
  }
  return false;
};