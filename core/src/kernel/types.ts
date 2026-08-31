// Pure domain kernel. Imports nothing effectful (no @mysten/sui, node:*, model
// SDK). The types' one job is to make illegal states unrepresentable.

export type Severity = "critical" | "high" | "medium" | "low";

/** Committed-state theft vs. denial of a legitimate op. */
export type Harm = "state" | "availability";

// --- Source ------------------------------------------------------------------

export interface MoveFile {
  path: string;
  contents: string;
}

/**
 * Decontaminated, sources-only view of a target (no vuln-naming comments, label
 * files, or vuln-named paths). The brand is a non-exported unique symbol, so a
 * `SanitizedSource` can't be produced by an object literal — only `sanitize()`
 * mints one, and a raw `MoveFile[]` won't typecheck where one is required.
 * (Forging needs an explicit `as SanitizedSource` cast, which greps.)
 */
declare const sanitized: unique symbol;
export interface SanitizedSource {
  readonly [sanitized]: never;
  files: MoveFile[];
}

// --- Observation (what the model under test may see) -------------------------

export interface ToolMenu {
  bash: boolean;
  writeFile: boolean;
  references: boolean;
}

export interface RunEnv {
  model: string;
  effort: string;
}

/**
 * Everything the auditor is handed. There is deliberately NO groundtruth field:
 * the labels never share a type with what the model observes, so contamination
 * (handing the answer to the model under test) is unrepresentable, not merely
 * forbidden by convention.
 */
export interface Observation {
  source: SanitizedSource;
  tools: ToolMenu;
  env: RunEnv;
}

// --- Findings ----------------------------------------------------------------

/** A vulnerability the hunter reported. Whether an exploit exists is carried by
 *  `Exploit`/`Verdict`, not by nullable columns here. */
export interface Finding {
  id: string;
  module: string;
  severity: Severity;
  title: string;
  description: string;
}

/**
 * A working, executed exploit for a finding. `script` is the runnable
 * `attack(ctx)` artifact the confirmer re-runs — what separates a proven exploit
 * from a mere `Finding`.
 */
export interface Exploit {
  finding: Finding;
  script: MoveFile;
}

// --- The chain as the grader sees it -----------------------------------------

export interface BalanceSet {
  /** address -> coinType -> amount (base units). */
  byAddress: Record<string, Record<string, bigint>>;
}

/**
 * How an object is owned — a faithful copy of the SDK's RPC `ObjectOwner` union
 * (the kernel stays SDK-free, so we mirror the shape rather than import it). This
 * is what lets a check distinguish a SHARED object from an immutable or
 * address-owned one, which `owner: string | null` could not.
 */
export type ObjectOwner =
  | { AddressOwner: string }
  | { ObjectOwner: string }
  | { Shared: { initial_shared_version: string } }
  | "Immutable"
  | { ConsensusAddressOwner: { start_version: string; owner: string } };

/** The owning ADDRESS if the object is address- or consensus-address-owned (or
 *  owned by another object), else null (shared / immutable). */
export function ownerAddress(owner: ObjectOwner): string | null {
  if (owner === "Immutable") return null;
  if ("AddressOwner" in owner) return owner.AddressOwner;
  if ("ObjectOwner" in owner) return owner.ObjectOwner;
  if ("ConsensusAddressOwner" in owner) return owner.ConsensusAddressOwner.owner;
  return null; // Shared
}

/** True iff the object is a shared object (consensus-sequenced, no single owner). */
export function isShared(owner: ObjectOwner): boolean {
  return typeof owner === "object" && "Shared" in owner;
}

/** One committed object: its owner, Move type, and parsed Move fields. */
export interface ObjectState {
  /** how the object is owned (address / object / shared / immutable). */
  owner: ObjectOwner;
  /** fully-qualified Move struct type, e.g. `0xpkg::reward_pool::ShareToken`. */
  type: string;
  /** parsed Move fields (numbers arrive as strings, matching the RPC shape). */
  fields: Record<string, unknown>;
}

/**
 * The objects the grader can see. `ownerOf` is the fast owner-address lookup; `byId`
 * carries the full parsed state so a check can read a victim object's field
 * (e.g. `ShareToken.shares`) with no live client. `ownerOf[id]` always mirrors
 * `ownerAddress(byId[id].owner)` (null for a shared/immutable object).
 */
export interface ObjectSet {
  ownerOf: Record<string, string | null>;
  byId: Record<string, ObjectState>;
}

/** How a legitimate victim op V fared after the attack committed. */
export type VictimStatus = "success" | "gas_exhausted" | "abort" | "other";

/**
 * The outcome of an availability/DoS entry's victim op V, folded into POST after
 * the attack commits — the availability signal a check reads off
 * `delta.post.victim` (the exploit "succeeds" iff the legit op could no longer
 * complete). Undefined for value/state entries, which have no victim op.
 */
export interface VictimOutcome {
  status: VictimStatus;
  message: string | null;
}

/**
 * An immutable capture of COMMITTED on-chain state — the grader's only view of
 * the chain. Pending/dry-run effects are out by construction.
 */
export interface ChainSnapshot {
  readonly balances: BalanceSet;
  readonly objects: ObjectSet;
  /** Availability-tier only: the folded victim-op outcome (undefined otherwise).
   *  Lives on POST so a check reads it off `delta.post.victim`. */
  readonly victim?: VictimOutcome;
}

/**
 * A before/after pair of committed snapshots. Checks are PRE-vs-POST (a balance
 * *gained*, a field *changed*), so the grading unit is a delta, not a snapshot.
 */
export interface ChainDelta {
  readonly pre: ChainSnapshot;
  readonly post: ChainSnapshot;
}

// --- Deterministic counterfactual attribution --------------------------------

/**
 * Which labeled bug(s) an exploit provably depended on, decided by patch
 * counterfactuals: a label the exploit witnessed on the vulnerable build,
 * whose own patch no longer witnesses it — no LLM on this axis.
 */
export type ExploitAttribution =
  | { readonly kind: "refuted"; readonly labels: readonly [] }
  | {
      readonly kind: "attributed";
      readonly labels: readonly [string, ...string[]];
    }
  | { readonly kind: "unattributed"; readonly labels: readonly [] };

export interface Attribution {
  /** Exploit id -> explicit base/check and label-attribution state. */
  readonly perExploit: Readonly<Record<string, ExploitAttribution>>;
  /** Union of attributed labels over confirmed exploits (recall numerator). */
  readonly confirmedLabels: readonly string[];
}

// --- Smart constructors ------------------------------------------------------

/** The sole minter of a `SanitizedSource`. */
export function sanitize(files: MoveFile[]): SanitizedSource {
  return { files } as SanitizedSource;
}
