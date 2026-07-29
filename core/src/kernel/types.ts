// Pure domain kernel. Imports nothing effectful (no @mysten/sui, node:*, model
// SDK). The types' one job is to make illegal states unrepresentable.

export type Severity = "critical" | "high" | "medium" | "low";

export type Network = "devnet" | "mainnet" | "none";

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
  network: Network;
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

/** One committed object: its owner, Move type, and parsed Move fields. */
export interface ObjectState {
  /** owning address, or null for shared/immutable. */
  owner: string | null;
  /** fully-qualified Move struct type, e.g. `0xpkg::reward_pool::ShareToken`. */
  type: string;
  /** parsed Move fields (numbers arrive as strings, matching the RPC shape). */
  fields: Record<string, unknown>;
}

/**
 * The objects the grader can see. `ownerOf` is the fast owner lookup; `byId`
 * carries the full parsed state so a check can read a victim object's field
 * (e.g. `ShareToken.shares`) with no live client. `ownerOf[id]` always mirrors
 * `byId[id].owner`.
 */
export interface ObjectSet {
  ownerOf: Record<string, string | null>;
  byId: Record<string, ObjectState>;
}

export interface EventLog {
  events: { type: string; sender: string; data: unknown }[];
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
  readonly events: EventLog;
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

// --- Verdict -----------------------------------------------------------------

/**
 * The result of grading one exploit. `confirmed` REQUIRES both the exploit and
 * a `ChainSnapshot` proof — a confirmed verdict with no evidence is a compile
 * error, which is the entire point of this module.
 */
export type Verdict =
  | { kind: "confirmed"; exploit: Exploit; proof: ChainSnapshot }
  | { kind: "refuted"; exploit: Exploit; reason: string }
  | { kind: "false_positive"; reason: string };

// --- Deterministic counterfactual attribution --------------------------------

/**
 * Which labeled bug(s) an exploit provably depended on, decided by patch
 * counterfactuals (exploit works on the vulnerable build ∧ breaks under a
 * label's patch) — no LLM on this axis.
 */
export interface Attribution {
  /**
   * exploit id -> attributed label ids. The SOLE source of truth for
   * confirmed-tier scoring: an EMPTY entry is a false positive (unions
   * base=false with base=true-but-patch-invariant). Attributed / exploit-carrying
   * / false-positive counts all derive from here.
   */
  perExploit: Record<string, string[]>;
  /** Union of attributed labels over confirmed exploits (recall numerator). */
  confirmedLabels: string[];
}

// --- Actions the hunter can take ---------------------------------------------

export type Action =
  | { kind: "run_bash"; command: string }
  | { kind: "write_file"; file: MoveFile }
  | { kind: "read_reference"; name: string }
  | { kind: "report_exploit"; exploit: Exploit };

// --- Smart constructors ------------------------------------------------------

/** The sole minter of a `SanitizedSource`. */
export function sanitize(files: MoveFile[]): SanitizedSource {
  return { files } as SanitizedSource;
}

export function confirmed(exploit: Exploit, proof: ChainSnapshot): Verdict {
  return { kind: "confirmed", exploit, proof };
}

export function refuted(exploit: Exploit, reason: string): Verdict {
  return { kind: "refuted", exploit, reason };
}

export function falsePositive(reason: string): Verdict {
  return { kind: "false_positive", reason };
}
