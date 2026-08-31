// The `Check` contract + reusable snapshot READERS. A check is an injected pure
// function over a `ChainDelta` (pre + post `ChainSnapshot`), the entry's bound
// params, and read-only on-chain evidence from the attack phase — no live
// client — returning the set of entry-local label IDs ("witnesses") the run
// demonstrates. Every datum a check needs (balances, owned + shared objects
// with parsed fields, attack-transaction events) must be IN the delta or the
// evidence. The per-entry predicates themselves live WITH the corpus entry;
// the kernel owns only this contract, the authoring guard, and the readers.
import type { ChainSnapshot, ChainDelta } from "./types.js";
import { ownerAddress, isShared } from "./types.js";

/** One Move event emitted by an attack transaction. */
export interface MoveEventEvidence {
  readonly type: string;
  readonly json: unknown;
}

/** One attack-phase transaction: its committed status and the events it
 *  emitted (failed transactions still appear, but with events irrelevant to
 *  grading — see `successfulMoveEvents`). */
export interface AttackTransactionEvidence {
  readonly digest: string;
  readonly status: "success" | "failure";
  readonly events: readonly MoveEventEvidence[];
}

/** Read-only, SDK-free evidence from the untrusted attack phase: only
 *  digests drained from that phase, in drained order, with per-transaction
 *  event order preserved. */
export interface CheckEvidence {
  readonly attackTransactions: readonly AttackTransactionEvidence[];
}

/** The set of entry-local label IDs a check run demonstrates. Empty means
 *  refuted. */
export interface CheckResult {
  readonly witnesses: readonly string[];
}

/** A pure function over a `ChainDelta`, the entry's bound params, and
 *  read-only attack-phase evidence — returns the witnessed label IDs. */
export type Check = (
  delta: ChainDelta,
  params: CheckParams,
  evidence: CheckEvidence,
) => CheckResult;

export interface CheckParams {
  packageId: string;
  attackerAddress: string;
  /** The admin/deployer address, for object-ownership anchors. */
  adminAddress?: string;
  /** The victim/user address, for object-field anchors. */
  userAddress?: string;
}

/**
 * The authoring guard for a `Check`'s return value. `check.ts` is trusted,
 * reviewed, in-repo code compile-checked against `Check` — this is not an
 * adversarial-input validator. It requires an object with an array
 * `witnesses` of non-empty strings, rejects (does not dedupe) duplicate IDs,
 * validates every ID against `allowedWitnessIds` (the entry's manifest label
 * IDs), and returns a deterministically sorted COPY. It ignores prototypes
 * and unrelated extra keys, and never mutates the input or freezes the
 * output.
 */
export function validateCheckResult(
  value: unknown,
  allowedWitnessIds: readonly string[],
  context?: string,
): CheckResult {
  const where = context ? ` (${context})` : "";
  if (typeof value !== "object" || value === null) {
    throw new Error(
      `check result${where} must be an object with a "witnesses" array, got ${typeof value}`,
    );
  }
  const raw = (value as { witnesses?: unknown }).witnesses;
  if (!Array.isArray(raw)) {
    throw new Error(
      `check result${where}.witnesses must be an array, got ${typeof raw}`,
    );
  }
  const allowed = new Set(allowedWitnessIds);
  const seen = new Set<string>();
  const witnesses: string[] = [];
  for (const w of raw) {
    if (typeof w !== "string" || w.length === 0) {
      throw new Error(
        `check result${where}.witnesses must contain only non-empty strings, got ${JSON.stringify(w)}`,
      );
    }
    if (seen.has(w)) {
      throw new Error(
        `check result${where}.witnesses contains duplicate id "${w}"`,
      );
    }
    seen.add(w);
    if (!allowed.has(w)) {
      throw new Error(
        `check result${where}.witnesses contains unknown id "${w}" (allowed: ${[...allowed].sort().join(", ")})`,
      );
    }
    witnesses.push(w);
  }
  return { witnesses: witnesses.sort() };
}

/** The only helper that invokes a `Check` — calls it, then applies
 *  `validateCheckResult` exactly once against the entry's allowed witness
 *  IDs. */
export function runCheck(
  check: Check,
  allowedWitnessIds: readonly string[],
  delta: ChainDelta,
  params: CheckParams,
  evidence: CheckEvidence,
  context?: string,
): CheckResult {
  return validateCheckResult(
    check(delta, params, evidence),
    allowedWitnessIds,
    context,
  );
}

/** Every event of `eventType` (canonical-form matched) emitted by a
 *  successful attack transaction, in transaction and event order. Events
 *  from failed transactions never contribute. */
export function successfulMoveEvents(
  evidence: CheckEvidence,
  eventType: string,
): readonly MoveEventEvidence[] {
  const wanted = normalizeType(eventType);
  const out: MoveEventEvidence[] = [];
  for (const tx of evidence.attackTransactions) {
    if (tx.status !== "success") continue;
    for (const event of tx.events) {
      if (normalizeType(event.type) === wanted) out.push(event);
    }
  }
  return out;
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
    if (ownerAddress(obj.owner) === owner && normalizeType(obj.type) === wanted) {
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

/** Every SHARED object of type `type` — a shared object is owned by nobody, so
 *  it never appears in `ownedObjects`; the confirmer discovers it from the tx
 *  object-changes. */
export function sharedObjects(
  snap: ChainSnapshot,
  type: string,
): { fields: Record<string, unknown> }[] {
  const wanted = normalizeType(type);
  const out: { fields: Record<string, unknown> }[] = [];
  for (const obj of Object.values(snap.objects.byId)) {
    if (isShared(obj.owner) && normalizeType(obj.type) === wanted) {
      out.push({ fields: obj.fields });
    }
  }
  return out;
}

/** The parsed `fields` of the (first) shared object of type `type`, or null. */
export function sharedObjectFields(
  snap: ChainSnapshot,
  type: string,
): Record<string, unknown> | null {
  const [first] = sharedObjects(snap, type);
  return first ? first.fields : null;
}

/** The `Clock`'s `timestamp_ms`, matched by type (`0x2::clock::Clock`) because
 *  the snapshot keys `0x6` under its zero-padded id, or null if absent. */
export function clockTimestampMs(snap: ChainSnapshot): bigint | null {
  const wanted = normalizeType("0x2::clock::Clock");
  for (const obj of Object.values(snap.objects.byId)) {
    if (normalizeType(obj.type) === wanted) {
      return fieldAsBigInt(obj.fields, "timestamp_ms");
    }
  }
  return null;
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
