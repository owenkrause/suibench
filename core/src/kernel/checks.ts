// The `Check` contract + reusable snapshot READERS. A check is an injected pure
// predicate over a `ChainDelta` (pre + post `ChainSnapshot`) — no live client —
// so every datum it needs (balances, owned objects with parsed fields, events)
// must be IN the snapshot. The per-entry predicates themselves live WITH the
// corpus entry; the kernel owns only this contract, the runner, and the readers.
import type { ChainSnapshot, ChainDelta, Verdict, Exploit } from "./types.js";
import { confirmed, refuted } from "./types.js";

/** A pure success predicate over a `ChainDelta` + the entry's bound params. The
 *  kernel lifts a true result into a `confirmed` Verdict (post snapshot as proof). */
export type Check = (delta: ChainDelta, params: CheckParams) => boolean;

export interface CheckParams {
  packageId: string;
  attackerAddress: string;
  /** The admin/deployer address, for object-ownership anchors. */
  adminAddress?: string;
  /** The victim/user address, for object-field anchors. */
  userAddress?: string;
}

// --- snapshot readers (the client-free primitives a corpus check reads) ------

/**
 * `addr`'s balance of `coinType`, matching coin types by canonical form.
 * `getAllBalances` intermittently stores a type with its package address in
 * short form (leading zeros stripped), so an exact-key miss falls back to a
 * normalized scan — otherwise a check keying off the 64-char packageId reads 0
 * (a grading false-negative).
 */
export function balanceAt(
  snap: ChainSnapshot,
  addr: string,
  coinType: string,
): bigint {
  const owned = snap.balances.byAddress[addr];
  if (!owned) return 0n;
  const direct = owned[coinType];
  if (direct !== undefined) return direct;
  const wanted = normalizeType(coinType);
  for (const [storedType, amount] of Object.entries(owned)) {
    if (normalizeType(storedType) === wanted) return amount;
  }
  return 0n;
}

/** `post - pre` for `addr`'s `coinType`. Missing entries read as 0; can be negative. */
export function balanceGained(
  delta: ChainDelta,
  addr: string,
  coinType: string,
): bigint {
  return (
    balanceAt(delta.post, addr, coinType) - balanceAt(delta.pre, addr, coinType)
  );
}

/** Every object of type `type` owned by `owner`, read straight from
 *  `snapshot.objects.byId` (no live client). */
export function ownedObjects(
  snap: ChainSnapshot,
  owner: string,
  type: string,
): { fields: Record<string, unknown> }[] {
  const wanted = normalizeType(type);
  const out: { fields: Record<string, unknown> }[] = [];
  for (const obj of Object.values(snap.objects.byId)) {
    if (obj.owner === owner && normalizeType(obj.type) === wanted) {
      out.push({ fields: obj.fields });
    }
  }
  return out;
}

/** The parsed `fields` of the (first) object of type `type` owned by `owner`,
 *  or null — read straight from `snapshot.objects.byId`, no live client. */
export function ownedObjectFields(
  snap: ChainSnapshot,
  owner: string,
  type: string,
): Record<string, unknown> | null {
  const [first] = ownedObjects(snap, owner, type);
  return first ? first.fields : null;
}

/** Read a numeric Move field (RPC delivers numbers as strings) as a bigint. */
export function fieldAsBigInt(
  fields: Record<string, unknown>,
  name: string,
): bigint | null {
  const raw = fields[name];
  if (raw === undefined || raw === null) return null;
  if (typeof raw === "bigint") return raw;
  if (typeof raw === "number" || typeof raw === "string") return BigInt(raw);
  return null;
}

/** Canonicalize a struct tag's addresses: pad each `0x…` to 64 hex chars. */
export function normalizeType(type: string): string {
  return type.replace(/0x[0-9a-fA-F]+/g, (m) => {
    const hex = m.slice(2).replace(/^0+/, "");
    return "0x" + hex.padStart(64, "0");
  });
}

/**
 * Lift a boolean `Check` into a `Verdict`: a true predicate becomes a
 * `confirmed` verdict carrying the POST snapshot as its committed-state proof;
 * false becomes `refuted`.
 */
export function runCheck(
  check: Check,
  delta: ChainDelta,
  params: CheckParams,
  exploit: Exploit,
): Verdict {
  return check(delta, params)
    ? confirmed(exploit, delta.post)
    : refuted(exploit, "success predicate not met on committed state");
}
