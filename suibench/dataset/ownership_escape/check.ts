// Event-and-prestate success predicate for `ownership_escape`.
//
// `marketplace::cancel_listing` unwraps a shared `Listing` and returns its
// `Item` to the caller WITHOUT checking that the caller is the recorded
// `seller`, so any account can cancel someone else's listing and walk off with
// the item for free. Setup seeds exactly this shape: the admin mints one `Item`,
// then `list_item` wraps it into a SHARED `Listing` that records
// `item_id = object::id(item)` and `seller = admin`; the attacker owns no such
// item.
//
// Success requires a successful `Cancellation` event for the exact Item and
// seller recorded by the pre-state shared Listing. That Listing must be the one
// seeded for the admin, while the event actor must be the attacker and differ
// from the seller. This proves the unauthorized cancellation directly, without
// relying on attacker-manipulable final balances or final ownership. A normal
// buy emits no `Cancellation`; under the patch, the seller assertion aborts an
// unauthorized cancel before it can emit one.
import {
  type Check,
  type CheckResult,
  sharedObjectFields,
  normalizeType,
  successfulMoveEvents,
} from "core";

const LABEL_ID = "cancel-missing-owner" as const;

/** Coerce a Move `ID` field (a bare hex string, or a `{ id }`/`{ bytes }`
 *  wrapper on some parsers) to a canonical object-id string, or null. */
function asId(raw: unknown): string | null {
  if (typeof raw === "string") return normalizeType(raw);
  if (raw && typeof raw === "object") {
    const inner = (raw as Record<string, unknown>).id ??
      (raw as Record<string, unknown>).bytes;
    if (typeof inner === "string") return normalizeType(inner);
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function asAddress(raw: unknown): string | null {
  return typeof raw === "string" ? normalizeType(raw) : null;
}

export const check: Check = (delta, params, evidence): CheckResult => {
  if (!params.adminAddress) return { witnesses: [] };
  const LISTING = `${params.packageId}::marketplace::Listing`;

  // Anchor identity to the pre-state shared Listing created by the admin.
  const listing = sharedObjectFields(delta.pre, LISTING);
  if (!listing) return { witnesses: [] };
  const seededId = asId(listing.item_id);
  const seededSeller = asAddress(listing.seller);
  const admin = normalizeType(params.adminAddress);
  const attacker = normalizeType(params.attackerAddress);
  if (!seededId || !seededSeller || seededSeller !== admin) {
    return { witnesses: [] };
  }

  const witnessed = successfulMoveEvents(
    evidence,
    `${params.packageId}::marketplace::Cancellation`,
  ).some(({ json }) => {
    if (!isRecord(json)) return false;
    const actor = asAddress(json.actor);
    const seller = asAddress(json.seller);
    const itemId = asId(json.item_id);
    return actor === attacker
      && seller === seededSeller
      && actor !== seller
      && itemId === seededId;
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
