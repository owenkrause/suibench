import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { ReferenceLibrary } from "./agent.js";

export interface ReferenceEntry {
  name: string;
  description: string;
  file: string;
  tokens: number;
}

export const REFERENCE_CATALOG: ReferenceEntry[] = [
  // ── Core patterns ─────────────────────────────────────────────
  {
    name: "sui-patterns",
    description:
      "44 Sui-specific vulnerability patterns (SUI-01 to SUI-44): object ownership confusion, shared object reentrancy, witness/OTW abuse, capability theft, PTB composability attacks, dynamic field injection, clock manipulation, transfer policy bypass",
    file: "sui-patterns.md",
    tokens: 17300,
  },
  {
    name: "common-move",
    description:
      "Chain-agnostic Move security patterns: access control, arithmetic (incl. 2.6 fixed-point overflow, 12.1 abort-before-checkpoint deadlock — the #1 missed bug class), resource safety, logic errors, input validation, cross-module interactions, upgradeability",
    file: "common-move.md",
    tokens: 15700,
  },
  {
    name: "false-positive-catalog",
    description:
      "70+ false positive patterns to avoid. Rationalizations table, 5-point self-hallucination check, Sui object model FPs, Move type system FPs, abort semantics FPs, DeFi design pattern FPs. Load this BEFORE finalizing findings.",
    file: "false-positive-catalog.md",
    tokens: 4300,
  },

  // ── Methodology ───────────────────────────────────────────────
  {
    name: "audit-methodology",
    description:
      "8-phase audit workflow from Panther Audits. Phase 7 is most valuable: 8-dimension Move-expert disproof, kill questions, dual narrative test, root-cause dedup, confidence gating, post-confirmation subsystem checks",
    file: "audit-methodology.md",
    tokens: 7700,
  },
  {
    name: "confidence-gates",
    description:
      "Multi-signal confidence model: 8 signal strength levels, hard evidence requirements per finding type (math proof, data flow trace, PoC), completeness thresholds, 6-gate gating checklist",
    file: "confidence-gates.md",
    tokens: 2450,
  },
  {
    name: "checklist-router",
    description:
      "Signal-to-file routing table: maps code keywords/patterns to the right reference files. Includes escalation rules and the #1 missed bug class callout for fixed-point libraries",
    file: "checklist-router.md",
    tokens: 1000,
  },
  {
    name: "audit-prompts",
    description:
      "MVD-derived targeted audit prompts: attack surface mapping, asset flow tracing, arithmetic deep-dive, resource safety, state machine analysis, external dependency review, initialization checks. Battle-tested heuristics.",
    file: "audit-prompts.md",
    tokens: 5450,
  },
  {
    name: "judging",
    description:
      "4-gate finding validation (refutation, reachability, trigger, impact). Confidence scoring with deductions. Safe patterns list for quick FP filtering. Multi-agent convergence rules.",
    file: "judging.md",
    tokens: 880,
  },
  {
    name: "shared-rules",
    description:
      "Cross-module pattern weaponization: when you find a bug in one module, systematically check every other module for the same pattern. Output format rules, finding classification (LEAD vs FINDING).",
    file: "shared-rules.md",
    tokens: 630,
  },

  // ── DeFi deep-dives ───────────────────────────────────────────
  {
    name: "defi-vectors",
    description:
      "DeFi overview + subcategory router (DEFI-01 to DEFI-10): oracle manipulation, flash loans, pool manipulation, loan invariants, reward calculation, liquidation, slippage, interest rates, governance, bridges. Load this first for any DeFi protocol — it tells you which deep-dive files to pull next.",
    file: "defi-vectors.md",
    tokens: 3100,
  },
  {
    name: "defi-lending",
    description:
      "Lending protocol patterns (DEFI-25 to DEFI-34, 80, 82, 84): health factor checks, solvency gaps, borrow cap bypass, EMA/spot asymmetry, pause symmetry (pausing repay locks funds), token denylist blocking, rate model retroactivity",
    file: "defi-lending.md",
    tokens: 6700,
  },
  {
    name: "defi-math-precision",
    description:
      "Math/precision patterns (DEFI-35 to DEFI-42, 85-87): division ordering, rounding direction, bit-shift overflow, fixed-point library overflow before checkpoint (DEFI-85/86 — the #1 missed Critical), accumulator deadlock, recoverability matrix",
    file: "defi-math-precision.md",
    tokens: 5650,
  },
  {
    name: "defi-liquidation",
    description:
      "Liquidation patterns (DEFI-50 to DEFI-66, 81, 83): no incentive, griefing, dust positions, bonus manipulation, partial liquidation traps, idle cash check, ADL debt source mismatch, close factor atomicity, grace period after unpause",
    file: "defi-liquidation.md",
    tokens: 5550,
  },
  {
    name: "defi-oracle",
    description:
      "Oracle patterns (DEFI-17 to DEFI-24): stale prices, confidence intervals, circuit breakers, multi-oracle inconsistency, Pyth/Switchboard integration bugs, depeg handling, TWAP vs spot",
    file: "defi-oracle.md",
    tokens: 3550,
  },
  {
    name: "defi-staking",
    description:
      "Staking patterns (DEFI-11 to DEFI-16): first depositor attack (no dead shares), reward setup timing, accumulator manipulation, flash deposit griefing, reward dilution",
    file: "defi-staking.md",
    tokens: 3000,
  },
  {
    name: "defi-slippage",
    description:
      "Slippage/DEX patterns (DEFI-43 to DEFI-49): zero min-output, missing deadline, multi-hop price degradation, hardcoded slippage, sandwich attack surfaces",
    file: "defi-slippage.md",
    tokens: 3100,
  },

  // ── Attack vectors (143 total) ────────────────────────────────
  {
    name: "attack-vectors-1",
    description:
      "Vectors 1-30: object model, abilities (copy/drop/store/key), visibility, access control, capability leakage, OTW validation, type safety, transfer policies. Each vector has built-in FP gates.",
    file: "attack-vectors-1.md",
    tokens: 3300,
  },
  {
    name: "attack-vectors-2",
    description:
      "Vectors 31-60: shared object races, PTB flash loans, hot potato bypasses, MEV/front-running, DoS via tx spam, clock/time manipulation, upgrade security, pause mechanism gaps",
    file: "attack-vectors-2.md",
    tokens: 3450,
  },
  {
    name: "attack-vectors-3",
    description:
      "Vectors 61-90: arithmetic safety, fixed-point overflow, division ordering, integer casting, rounding exploitation, vault share inflation, dynamic field orphaning, balance desync, fee logic errors",
    file: "attack-vectors-3.md",
    tokens: 3100,
  },
  {
    name: "attack-vectors-4",
    description:
      "Vectors 91-120: oracle staleness (Pyth/Switchboard), DeFi protocol patterns, staking accumulator bugs, liquidation mechanics, retroactive pricing, bridge supply invariants, governance flash-voting",
    file: "attack-vectors-4.md",
    tokens: 2950,
  },
  {
    name: "attack-vectors-5",
    description:
      "Vectors 121-143: generic type confusion (#1 critical), entry visibility bypass, event spoofing, flash loan receipt binding, wrapper attacks, dependency version contagion, denylist epoch gap. Real-world exploits (Navi, Econia, Cetus).",
    file: "attack-vectors-5.md",
    tokens: 4500,
  },

  // ── Agent methodologies ───────────────────────────────────────
  {
    name: "first-principles-agent",
    description:
      "Methodology: ignore known patterns, read the code's own logic, extract every implicit assumption (values, ordering, identity, arithmetic, state, abilities, ownership), systematically violate each. High-signal for novel bugs.",
    file: "first-principles-agent.md",
    tokens: 650,
  },
  {
    name: "invariant-agent",
    description:
      "Methodology: map every invariant (conservation laws, ability invariants, state couplings, capacity constraints). Break round-trips, exploit path divergence, break commutativity, abuse boundaries (zero, max u64).",
    file: "invariant-agent.md",
    tokens: 790,
  },
  {
    name: "economic-security-agent",
    description:
      "Methodology: PTB flash loan composition, oracle staleness exploitation, shared capacity starvation, token misbehavior (rebasing, hooks), weaponizing legitimate features. Every finding needs concrete economics (who profits, how much).",
    file: "economic-security-agent.md",
    tokens: 710,
  },
  {
    name: "execution-trace-agent",
    description:
      "Methodology: parameter divergence (claimed vs actual), value leaks (fee deducted but original forwarded), BCS encoding mismatches, stale reads after external calls, partial state updates, PTB composition attacks, operation interleaving.",
    file: "execution-trace-agent.md",
    tokens: 920,
  },
  {
    name: "sui-protocol-checklists",
    description:
      "Protocol-type checklists: lending (14 items), AMM (10), vault (10), staking (10), bridge (9), governance (6), NFT/kiosk (8), package upgrade (8). Load after identifying what type of protocol you're auditing.",
    file: "sui-protocol-agent.md",
    tokens: 1440,
  },

  // ── Formal verification ────────────────────────────────────────
  {
    name: "sui-prover-specs",
    description:
      "Sui Prover formal verification: full syntax (#[spec(prove)], requires/ensures, .to_int()/.to_real(), ghost variables, loop invariants), setup workflow (copy package, fix Move.toml, write specs, run sui-prover), spec templates for overflow/rounding/monotonicity/boundaries/state invariants/events, interpreting output (counterexamples = confirmed bugs), common pitfalls",
    file: "sui-prover-specs.md",
    tokens: 3100,
  },

  // ── Specialized ───────────────────────────────────────────────
  {
    name: "semantic-gap-checks",
    description:
      "Stale state detection: gap taxonomy (SYNC_GAP, CONDITIONAL_SKIP, ACCUMULATION_EXPOSURE, LIFECYCLE_GAP, DUAL_SOURCE_METRIC), 5-step workflow, high-signal keyword targets (reward_per_share, accumulator, checkpoint, last_update)",
    file: "semantic-gap-checks.md",
    tokens: 720,
  },
];

// src/runtime -> package root -> references/ (same in dist/runtime).
const REFERENCES_DIR = resolve(import.meta.dirname, "../../references");

export function listReferences(): string {
  return REFERENCE_CATALOG.map(
    (r) =>
      `- **${r.name}** (~${Math.round(r.tokens / 1000)}k tokens): ${r.description}`,
  ).join("\n");
}

export function readReference(name: string): string {
  const entry = REFERENCE_CATALOG.find((r) => r.name === name);
  if (!entry) {
    const available = REFERENCE_CATALOG.map((r) => r.name).join(", ");
    return `Error: unknown reference "${name}". Available references: ${available}`;
  }
  try {
    return readFileSync(resolve(REFERENCES_DIR, entry.file), "utf-8");
  } catch {
    return `Error: could not read reference file "${entry.file}".`;
  }
}

/** The curated reference library, as the agent's `ReferenceLibrary` port. */
export const referenceLibrary: ReferenceLibrary = {
  list: listReferences,
  read: readReference,
};
