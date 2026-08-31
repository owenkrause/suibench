// Shared Sui/Move/DeFi security knowledge, reused by every prompt builder
// (suibench's audit prompts, suixploit's audit-only prompts).
export const FOUNDATIONAL_CONTEXT = `## Sui/Move Security Foundations

### Object Ownership & Access Control
- **Address-owned**: only the owner can use in transactions. Fast path (no consensus, <500ms finality). Passing an owned object as a function parameter IS the access control — no separate signer check needed.
- **Shared**: anyone can reference in transactions. Must go through consensus for ordering. ALL access control must be implemented in Move code — there is no implicit owner gate.
- **Immutable**: cannot be mutated or deleted. No contention.
- **Wrapped**: objects stored inside other objects. Not directly accessible — must unwrap first. Can be used to hide state or create escrow patterns.
- **Dynamic fields**: key-value storage on objects. Namespace collisions possible if keys aren't unique. Orphaned dynamic fields persist after parent deletion.

### Capability Pattern
The primary access gate on Sui. If a function takes \`&AdminCap\` (owned), only the cap holder can call it.
- Capabilities with \`copy\` ability are dangerous: allows duplication, breaking uniqueness assumptions.
- Capabilities with \`store\` ability can be wrapped/transferred outside protocol control.
- Capabilities should typically have only \`key\` (or \`key, store\` if intentionally transferable).
- Check for consistency: if function A requires AdminCap but function B doing similar privileged work does not, that's a finding.

### Witness & One-Time Witness (OTW)
- Witness pattern: struct with only \`drop\` proves type ownership. Must NOT have \`copy\`.
- OTW: created once in \`init()\`, consumed immediately. Has uppercase module name. Must have \`drop\` only.
- If a witness type has \`copy\`, it can be duplicated to bypass one-time guarantees.

### Ability System
- \`key\`: object can be stored in global storage, has an \`id: UID\` field.
- \`store\`: can be stored inside other objects or transferred freely.
- \`copy\`: can be duplicated. Dangerous for capabilities, witnesses, or anything representing unique authority.
- \`drop\`: can be silently destroyed. Without \`drop\`, a value MUST be explicitly consumed (hot potato pattern).
- Linear types (no \`copy\` + no \`drop\`) enforce exactly-once consumption — used for flash loan receipts.
- \`Coin<T>\` has no \`copy\` — linear types prevent double-spend at the type system level.

### PTBs (Programmable Transaction Blocks)
- Up to 1,024 commands execute sequentially in ONE atomic transaction.
- Results from earlier commands can be inputs to later ones — enables composing arbitrary multi-step attacks atomically.
- If any command fails, ALL effects revert.
- \`public fun\` (not just \`entry\`) are PTB-callable. Attackers can call any public function, not just entry points.
- \`entry fun\` can only appear as the entry point of a PTB command (cannot chain results).
- **State inconsistency within PTBs**: if function A partially updates a shared object, function B in the same PTB sees the intermediate state. This enables attacks where per-call limits are bypassed by calling N times (e.g. close factor bypass via repeated liquidation in one PTB).
- Flash loans via PTBs: deposit → manipulate → withdraw atomically, with no hot potato needed if the protocol doesn't enforce it.

### Transaction Ordering
- No public mempool. Transactions are sent directly to validators.
- Shared-object transactions are ordered by Mysticeti consensus (DAG-based). No single block proposer controls order — front-running requires validator collusion.
- Owned-object transactions bypass consensus entirely (fast path).
- Race conditions between concurrent shared-object transactions ARE possible — order is non-deterministic.

### Move Type System Security
- **Integer overflow/underflow aborts by default** (no wrapping arithmetic). This is DoS, not corruption.
  BUT: if overflow occurs in an accumulator/reward update BEFORE a checkpoint write, the transaction aborts, the checkpoint never advances, and the time delta grows — causing PERMANENT deadlock on retry. This is the **abort-before-checkpoint pattern**, the #1 missed Critical/High bug class in Move audits.
- No dynamic dispatch, no callbacks, no reentrancy in the Solidity sense.
- Generics are monomorphized at compile time. Types must satisfy ability constraints.
- \`public(package)\` restricts callers to the same package — but within a package, all modules can call each other.
- Division truncates toward zero. Precision loss in integer division is real and exploitable (especially in share/rate calculations).
- **Implementation-level math bugs are the #1 exploited class on Sui.** The Cetus exploit ($230M) was a single off-by-one in a shift boundary check: \`> 191\` instead of \`>= 192\`, allowing u256 overflow at exactly bit-width 192. After design-level analysis, systematically examine every arithmetic/math function:
  - Off-by-one in boundary checks: \`>\` vs \`>=\`, \`<\` vs \`<=\` — test at N-1, N, N+1 for every comparison threshold
  - Overflow at type-width boundaries: test with values near 2^64, 2^128, 2^192, 2^255
  - Truncation on downcasts: u256→u128, u128→u64 — compute whether intermediate results can exceed target type max
  - Multiply-before-divide overflow: \`a * b / c\` where the intermediate \`a * b\` exceeds type max before \`/ c\` normalizes (see DEFI-85 in \`defi-math-precision\`)
  - For suspicious math functions, use the Sui Prover to formally verify ALL possible inputs (see Sui Prover section below)

### DeFi Security Primitives
- **Oracle manipulation**: spot price derived from pool ratio is flash-loan manipulable. Require TWAP/EMA with staleness checks + confidence intervals.
- **Flash loans**: hot potato pattern (no drop/store/copy/key) guarantees same-tx repayment. Verify the receipt struct actually lacks all four abilities. If it has any, the flash loan can be circumvented.
- **Share/rate math**: first-depositor inflation attacks when vault starts at 0 shares. Check initial share minting, rounding direction (should favor the protocol), and dead share mechanisms.
- **Accumulator patterns**: reward_per_share, interest indices, checkpoint timestamps. If these overflow or skip updates on certain code paths, accounting diverges permanently.
- **Slippage**: any swap/withdrawal without min_amount_out is sandwich-attackable.
- **Pause symmetry**: pausing borrow without unblocking liquidation creates bad debt. Pausing repay locks user funds.

### Key False Positive Traps
- Owned object parameter = access control. Don't report "missing auth check" when a function takes an owned capability.
- Move overflow = abort, not corruption. Only report if attacker profits from DoS or if abort-before-checkpoint bricks state.
- Linear types prevent double-spend (\`Coin<T>\` has no \`copy\`).
- Hot potato is compiler-enforced — no runtime bypass is possible.
- "Pattern looks dangerous" is not analysis. Trace the actual data flow and write the exact PTB exploit sequence. If you can't write the exploit, it probably doesn't exist.`;
