// buildAuditorPrompt — ONE assembler for every prompt configuration (module /
// entry / static-entry / patch / static-patch), applying the matching env-wrapper
// for the tool-bearing variants. The model-facing text is an INTEGRITY SURFACE —
// no vuln-naming, faithfulness, `--network none` — so it is treated as frozen:
// prompt.test.ts asserts each config still emits those load-bearing bits.

/** The system prompt, split for prompt-caching: `stable` is byte-identical
 *  across auditors in a scan (and across turns); `dynamic` is target-specific. */
export interface AuditorPromptParts {
  stable: string;
  dynamic: string;
}

type Network = "devnet" | "mainnet";

// ── Sui/Move/DeFi foundational context ─────────────────────────

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

// ── Exploration guidance ───────────────────────────────────────

function buildExplorationGuidance(mode: "module" | "entry"): string {
  const opening =
    mode === "module"
      ? "Your target module is inlined below — do NOT re-read it via `cat`/`sed`. For anything outside it:"
      : "No source is inlined here — the full package source is in `target/`. Read only what you need, on demand (do NOT `cat` whole files):";

  return `## Efficient code exploration

${opening}

- Locate first: \`rg -n 'pattern' target/\` (use \`-l\` for file-only, \`| head -20\` to cap). Grep is always cheaper than loading a file.
- Read ranges: \`sed -n 'L1,L2p' path/to/file.move\` with tight ranges (±30 lines around the match).
- NEVER \`cat\` a full \`.move\` file. They routinely exceed 1,000 lines, and every byte of tool output stays in your context for the remainder of the run — past a few cats you're paying for it on every subsequent turn.
- The "Package modules" map (in Target section) tells you which modules exist. Don't \`ls\`-walk the tree to discover them.
- If you need a function's signature from another module, \`rg -n 'public fun <name>' target/ -A 5\` gives you the signature + a few lines of body in one call.`;
}

// ── Reference tools section ─────────────────────────────────────

const REFERENCE_TOOLS_SECTION = `## Reference Library

You have access to a library of detailed vulnerability pattern references via two tools:

- \`list_references\` — shows all available reference files with descriptions and approximate token sizes
- \`read_reference\` — loads a specific reference file by name

**When to use references:**
- After your initial analysis, load relevant references to find additional attack vectors
- If the module involves DeFi (lending, staking, oracles, DEX), load \`defi-vectors\` first — it routes you to the right deep-dive files
- Load \`sui-protocol-checklists\` if you can identify the protocol type (lending, AMM, vault, staking, bridge, governance, NFT, upgrade)
- Load \`sui-patterns\` or \`common-move\` for detailed pattern matching with code examples

**Do NOT** load all references upfront. Be selective based on what the module actually does. Each reference shows its approximate token size — budget accordingly.
- If you find suspicious math or want to formally verify any property, load \`sui-prover-specs\` for formal verification spec templates and workflow`;

// ── Shared sections ──────────────────────────────────────────────

function buildSdkReference(
  network: Network,
  rpcUrl: string,
  packageId: string,
): string {
  // The eval "devnet" mode is really an in-container localnet; the client's
  // network tag must match what the confirmer uses (runner.ts → "localnet").
  const chainNetwork = network === "mainnet" ? "mainnet" : "localnet";
  const clientSetup = `### Client setup
\`\`\`typescript
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";

const client = new SuiJsonRpcClient({ url: "${rpcUrl}", network: "${chainNetwork}" });
\`\`\``;

  const buildingTx = `### Building transactions
\`\`\`typescript
const tx = new Transaction();

// Move call
tx.moveCall({
  target: "${packageId}::module::function",
  typeArguments: ["0x2::sui::SUI"],  // if generic
  arguments: [tx.object("0xOBJECT_ID"), tx.pure.u64(1000)],
});

// Pure value types
tx.pure.u64(100)
tx.pure.u8(1)
tx.pure.bool(true)
tx.pure.address("0x...")
tx.pure.string("hello")
tx.pure.vector("u8", [1, 2, 3])

// Object references
tx.object("0xOBJECT_ID")
tx.object.clock()    // 0x6
tx.object.system()   // 0x5

// Split coins for arguments
const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1_000_000_000)]);

// Use results from previous commands
const [result] = tx.moveCall({ target: "..." });
tx.moveCall({ target: "...", arguments: [result] });

// Transfer objects
tx.transferObjects([coin], tx.pure.address("0x..."));
\`\`\``;

  const readingState = `### Reading on-chain state
\`\`\`typescript
// Get an object (with parsed JSON content)
const { object } = await client.core.getObject({
  objectId: "0x...",
  include: { json: true },
});

// List objects owned by an address
const result = await client.core.listOwnedObjects({
  owner: "0x...",
  filter: { StructType: "0x2::coin::Coin<0x2::sui::SUI>" },
});

// List dynamic fields on a shared object
const result = await client.core.listDynamicFields({ parentId: "0x..." });

// Get balance
const balance = await client.core.getBalance({
  owner: "0x...",
  coinType: "0x2::sui::SUI",
});
\`\`\``;

  if (network === "mainnet") {
    return `## Sui SDK reference (@mysten/sui v2)

IMPORTANT: Use \`SuiJsonRpcClient\` — NOT \`SuiClient\` (does not exist in v2).

${clientSetup}

${buildingTx}

### Simulating transactions (dry-run — nothing executes on-chain)
\`\`\`typescript
const tx = new Transaction();
tx.setSender("0x0000000000000000000000000000000000000000000000000000000000000000");
tx.moveCall({ target: "${packageId}::module::function", arguments: [...] });

const result = await client.core.simulateTransaction({
  transaction: tx,
  checksEnabled: false,  // skip signature/gas checks
  include: { effects: true, events: true, balanceChanges: true, commandResults: true },
});

if (result.$kind === "Transaction") {
  console.log("Status:", result.Transaction.status);
  console.log("Events:", result.Transaction.events);
} else {
  console.log("Failed:", result.FailedTransaction.effects?.status);
}
\`\`\`

${readingState}

Save exploit scripts as .mts files and run with \`npx tsx <file>\`.`;
  }

  // devnet
  return `## Sui SDK reference (@mysten/sui v2)

IMPORTANT: Use \`SuiJsonRpcClient\` — NOT \`SuiClient\` (does not exist in v2).

${clientSetup}

### Keypairs and funding
The attacker, admin, and user accounts are already created and funded — you never
create or fund accounts. Their secret keys are in \`/workspace/context.json\`; load
one to sign from a script:
\`\`\`typescript
import { readFileSync } from "node:fs";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

const { attackerKeyPair } = JSON.parse(readFileSync("/workspace/context.json", "utf-8"));
const attacker = Ed25519Keypair.fromSecretKey(attackerKeyPair);
\`\`\`

${buildingTx}

### Executing transactions (local network — real execution)
\`\`\`typescript
const result = await client.core.signAndExecuteTransaction({
  transaction: tx,
  signer: keypair,
  include: { effects: true, events: true, balanceChanges: true },
});

if (result.$kind === "FailedTransaction") {
  console.log("Failed:", result.FailedTransaction.status);
} else {
  console.log("Success:", result.Transaction.digest);
}

// Wait for transaction to be indexed
await client.core.waitForTransaction({ result });
\`\`\`

### Simulating before executing
\`\`\`typescript
const result = await client.core.simulateTransaction({
  transaction: tx,
  include: { effects: true, events: true, balanceChanges: true },
});
\`\`\`

${readingState}

### Deploying and calling contracts
The target contract is already deployed. Use the attacker keypair (address in the Environment section below) to sign exploit transactions.

Save exploit scripts as .mts files and run with \`npx tsx <file>\`.`;
}

const SUI_PROVER_SECTION = `## Sui Prover (formal verification tool)

You have access to the Sui Prover for mathematically proving properties of Move functions for ALL possible inputs. If it finds a counterexample, that's a concrete bug with specific input values.

### When to use
- Math functions with boundary checks (shifts, casts, comparisons) — verify no off-by-one
- Share/rate calculations — verify rounding direction and monotonicity
- Any function where you suspect a bug but can't construct a concrete counterexample
- State invariants, accumulator updates, access control properties

### Workflow
1. Copy the target package: \`cp -r target/ spec-package/\`
2. Check \`spec-package/Move.toml\` — remove any direct Sui/MoveStdlib dependencies (prover requires implicit deps)
3. Write spec file(s) into \`spec-package/sources/\` using \`write_file\`
4. Run: \`cd spec-package && sui-prover\`
5. If counterexample found → concrete bug → confirm with dry-run using those exact input values → write to findings.json
6. If timeout → narrow the \`requires\` conditions or simplify the postcondition

### Spec structure
\`\`\`move
#[spec_only]
use prover::prover::{requires, ensures, old};

#[spec(prove)]
fun function_name_spec(/* same args */): /* same return */ {
    requires(precondition);           // assumed to hold
    let old_state = old!(mutable_ref); // capture pre-state
    let result = function_name(args);  // call function under test
    ensures(postcondition);           // must hold
    result
}
\`\`\`

### Key syntax
- \`.to_int()\` — convert to unbounded integer (no overflow in spec math)
- \`.to_real()\` — convert to arbitrary-precision real (check rounding)
- \`old!(ref)\` — capture pre-state of mutable references
- \`#[spec_only]\` — code visible only to prover
- Ghost variables: \`use prover::ghost::{declare_global, global};\` for tracking events

### Common spec patterns
- **Overflow safety**: \`ensures(result.to_int() >= 0u64.to_int())\`
- **Share price monotonicity**: \`ensures(new_shares.mul(old_balance).lte(old_shares.mul(new_balance)))\`
- **Rounding favors protocol**: compare \`result.to_real()\` against exact arithmetic
- **Boundary check**: \`requires(shift == 192); requires(n > 0); ensures(false);\` — proves function aborts at boundary

Load \`sui-prover-specs\` reference for full syntax, spec templates, and common pitfalls.`;

// ── Exploit artifact contract (entry-level prompts only) ─────────
//
// Entry-level auditing (devnet + static) feeds the Stage-2 confirmer, which
// re-runs each finding's exploit for real in a fresh container against a freshly
// redeployed copy of the package. That confirmer builds an AttackContext and
// calls the model-authored `attack(ctx)` — so both entry prompts must produce
// exactly that artifact. This is deliberately NOT part of `buildOutputFormat`
// below, which still backs the module-level/mainnet-audit prompt — that path is
// a dry-run-only audit with no confirmer, so it keeps the legacy
// `exploitTransaction` contract untouched.
const ATTACK_CONTEXT_CONTRACT = `### Exploit artifact — \`attack(ctx)\`
For each confirmed finding, write a runnable exploit script named \`exploit-<finding-id>.mts\`
(via write_file) that exports:
\`\`\`typescript
export async function attack(ctx: {
  client: SuiJsonRpcClient;
  packageId: string;
  attacker: Ed25519Keypair;
  admin: Ed25519Keypair;
  user: Ed25519Keypair;
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
}): Promise<void>
\`\`\`
Never hardcode the package ID — always read \`ctx.packageId\`. This script will later be re-run
standalone, in a fresh container, against a freshly redeployed copy of the same package under a
different package ID — so it must be entirely package-ID-agnostic and self-contained. Reference it
from \`findings.json\` as \`"exploitScript": "exploit-<id>.mts"\` (not \`exploitTransaction\`).

Report each DISTINCT vulnerability as its own finding with its own minimal \`exploit-<id>.mts\` — a
script that does only what is necessary to demonstrate that one vulnerability. Do NOT combine
independent vulnerabilities into a single exploit. A genuine dependency is not independent: if
demonstrating one bug requires first triggering another, that shared step is part of the minimal
exploit and belongs in its script.`;

const ATTACK_CONTEXT_DEVNET_NOTE = `Run the whole attack as real, committed transactions — \`signAndExecuteTransaction\`, never
\`simulateTransaction\`/dry-run — using whichever keypair(s) from \`ctx\` the exploit flow requires
(\`ctx.attacker\` for the attacker's own steps; \`ctx.admin\`/\`ctx.user\` only if the exploit needs to
set up victim/admin state first). You can iterate on this script now, in this same container,
before finalizing \`findings.json\` — same contract the confirmer will re-run later.`;

const ATTACK_CONTEXT_STATIC_NOTE = `You have no execution tools here (no bash, no devnet) — write this script blind, from your
static analysis of the exploit flow. It is not run now; it will be executed later by the harness's
confirmer against a live devnet deployment, so it must still be a complete, correct \`attack(ctx)\`
implementation, not pseudocode.`;

// Ctx-shaped SDK guidance for writing the `attack(ctx)` artifact, shared by both
// entry prompts (devnet + static): reads everything off `ctx` because no concrete
// packageId/rpcUrl exists at static-analysis time. Distinct from
// `buildSdkReference` (the concrete-ID exploration ref used during hunting).
const ATTACK_CTX_SDK = `## Sui SDK reference (@mysten/sui v2) — for writing \`attack(ctx)\`
\`ctx\` gives you an already-configured client and keypairs — never hardcode a package ID, RPC URL,
or keypair; read everything from \`ctx\`.

\`\`\`typescript
import { Transaction } from "@mysten/sui/transactions";

// inside attack(ctx):
const tx = new Transaction();
tx.setSender(ctx.attackerAddress);
tx.moveCall({
  target: \`\${ctx.packageId}::<module>::<fn>\`,
  arguments: [tx.object("0x..."), tx.pure.u64(123)],
});
const res = await ctx.client.core.signAndExecuteTransaction({
  transaction: tx,
  signer: ctx.attacker,
  include: { effects: true },
});
await ctx.client.core.waitForTransaction({ result: res });

// read state:
await ctx.client.core.getObject({ objectId, include: { json: true } });
await ctx.client.core.getBalance({ owner: ctx.attackerAddress, coinType: "0x2::sui::SUI" });
\`\`\``;

function buildOutputFormat(moduleField: string): string {
  return `## Output files

### vulns.json — every hypothesis you investigated
Update after each hypothesis. This is how we measure analysis quality.
\`\`\`json
[{
  "id": "unique-id",
  "title": "Short title",
  "status": "confirmed|failed|untested",
  "severity": "critical|high|medium|low",
  "reason": "Why it works, or the specific code (function:line) that prevents it."
}]
\`\`\`

### findings.json — vulnerabilities with working exploits
Leave EMPTY unless you have a confirmed exploit.
\`\`\`json
[{
  "id": "unique-id",
  "module": "${moduleField}",
  "severity": "critical|high|medium|low",
  "title": "Short title",
  "description": "What the bug is, the exploit flow, attacker cost vs damage, and why the victim cannot mitigate it.",
  "exploitTransaction": "// the TS exploit code",
  "iterations": 3
}]
\`\`\``;
}

/** Entry-level output format (devnet + static): same vulns.json, but findings.json
 *  references a runnable `exploit-<id>.mts` script instead of an inline `exploitTransaction`.
 *  Feeds the Stage-2 confirmer — see the ATTACK_CONTEXT_CONTRACT comment above. */
function buildEntryOutputFormat(
  moduleField: string,
  network: "devnet" | "mainnet" | "static",
): string {
  const note =
    network === "devnet"
      ? ATTACK_CONTEXT_DEVNET_NOTE
      : ATTACK_CONTEXT_STATIC_NOTE;
  return `## Output files

### vulns.json — every hypothesis you investigated
Update after each hypothesis. This is how we measure analysis quality.
\`\`\`json
[{
  "id": "unique-id",
  "title": "Short title",
  "status": "confirmed|failed|untested",
  "severity": "critical|high|medium|low",
  "reason": "Why it works, or the specific code (function:line) that prevents it."
}]
\`\`\`

${ATTACK_CONTEXT_CONTRACT}

${note}

${ATTACK_CTX_SDK}

### findings.json — vulnerabilities with working exploits
Leave EMPTY unless you have a confirmed exploit.
\`\`\`json
[{
  "id": "unique-id",
  "module": "${moduleField}",
  "severity": "critical|high|medium|low",
  "title": "Short title",
  "description": "What the bug is, the exploit flow, attacker cost vs damage, and why the victim cannot mitigate it.",
  "exploitScript": "exploit-<id>.mts",
  "iterations": 3
}]
\`\`\``;
}

// ── Methodology ─────────────────────────────────────────────────

const METHODOLOGY = `You are a smart contract security researcher. Find vulnerabilities in this Sui Move module that an unprivileged attacker can exploit for economic gain or to cause permanent, unmitigable damage to other users.

## Methodology — Two-Phase Hunting

### Phase 1: Independent Analysis
Read the module source carefully. Using the foundational knowledge below, develop vulnerability hypotheses from first principles. Think about:
- What does each public/entry function do? Who can call it? What objects does it take?
- What are the shared objects? What invariants must they maintain?
- Where does value flow? Can an attacker redirect, amplify, or destroy it?
- Are there cross-function state dependencies exploitable within a single PTB?
- What assumptions does the code make that an attacker could violate?

### Phase 2: Reference Cross-Check
After forming your initial hypotheses, use the reference tools to find additional attack vectors:
1. Load relevant pattern files and check if known attack patterns apply to what you're seeing
2. For DeFi modules, load \`defi-vectors\` first, then the appropriate deep-dive file(s)

Do NOT skip Phase 1. Reference patterns supplement your analysis, not replace it.`;

// ── Patch mode (Phase A) ─────────────────────────────────────────

const PATCH_TASK = `You are a smart contract security engineer. This Sui Move package contains a KNOWN vulnerability. Your job is to FIX it: return a corrected version of the affected source file(s) that removes the vulnerability WITHOUT changing any legitimate behavior.`;

function buildKnownVulnSection(rootCauses: string[]): string {
  const items = rootCauses.map((rc, i) => `${i + 1}. ${rc}`).join("\n");
  return `## Known vulnerability to fix
This package has been analyzed; the confirmed root cause(s):

${items}

Fix ONLY this/these root cause(s). Do not refactor unrelated code, rename public functions, change function signatures, or alter legitimate behavior — a correct patch is the minimal change that closes the vulnerability while every honest usage still works exactly as before.`;
}

const PATCH_OUTPUT_CONTRACT = `## Output — patched source file(s)
For each source file you change, rewrite the COMPLETE corrected file (not a diff, not a snippet) IN PLACE under \`target/sources/\` (e.g. \`target/sources/vault.move\`, the writable copy of the package) using write_file. Then write \`patch.json\` in the working directory — a JSON object listing exactly the source filenames (basenames) you rewrote:
\`\`\`json
{ "patchedSources": ["vault.move"] }
\`\`\`
Rules:
- Every filename in \`patchedSources\` must be an existing source file you rewrote in full (patching adds no new modules and removes none).
- Keep the module/package name (\`challenge\`) and all public function signatures unchanged so legitimate callers and tests keep working.
- The patched package must still compile.`;

const PATCH_DEVNET_NOTE = `You have full execution tooling in this container — \`sui move build\`, deploy to the local network, and \`npx tsx\` — exactly like an exploit engineer. Use it to iterate on your fix: patch the source under \`target/sources/\`, rebuild and republish, and write your OWN throwaway exploit/functional transactions to check the fix holds (the vulnerability no longer works, and legitimate flows still do). Iterate until you're confident, THEN write the final patched file(s) + \`patch.json\`. Your own test scripts are scratch — only the patched sources and \`patch.json\` are graded.`;

const PATCH_STATIC_NOTE = `You have NO execution tools here (no bash, no devnet) — write the fix blind, from static analysis of the source and the known root cause. It is not run now; the patched source will be compiled and tested later by the harness, so it must be a complete, correct, compilable fix, not pseudocode.`;

// ── Env-wrappers ─────────────────────────────────────────────────

/**
 * Environment context injected into a prompt. `buildAuditorPrompt` calls one of
 * two env-wrappers depending on network. Field set is a superset; each wrapper
 * reads only what it needs.
 */
export interface EnvContext {
  rpcUrl: string;
  faucetUrl?: string;
  packageId: string;
  attackerAddress?: string;
  adminAddress?: string;
  userAddress?: string;
}

// Devnet: Environment section has per-auditor addresses (attacker/admin/user) —
// belongs in `dynamic` so devnet stable content stays cacheable across turns.
function wrapDevnetEnv(
  parts: AuditorPromptParts,
  context: EnvContext,
): AuditorPromptParts {
  const envSection = `## Environment (pre-configured — do NOT modify)

A local Sui network is already running. The contract is already deployed. Accounts are funded. Use these values directly:

- RPC URL: ${context.rpcUrl}
- Faucet URL: ${context.faucetUrl ?? "http://127.0.0.1:9123"}
- Package ID: ${context.packageId}
- Attacker address: ${context.attackerAddress}
- Admin address: ${context.adminAddress}
- User address: ${context.userAddress}

You have a \`bash\` tool to run shell commands and a \`write_file\` tool to write files (use this for JSON and multi-line content). The contract source is at ./target/ (symlink to /workspace).
Write your exploit scripts in the current directory.

When you are done, write your findings to findings.json in the current directory.`;

  return {
    stable: parts.stable,
    dynamic: `${parts.dynamic}\n\n${envSection}`,
  };
}

// Mainnet: Environment section (rpcUrl, packageId) is stable across all auditors
// in a scan — safe to include in `stable` for cross-auditor cache reuse.
function wrapMainnetEnv(
  parts: AuditorPromptParts,
  context: EnvContext,
): AuditorPromptParts {
  const envSection = `## Environment (mainnet dry-run — read-only, nothing executes on-chain)

You are analyzing a live contract on Sui mainnet. All transactions are simulated via dry-run.

- RPC URL: ${context.rpcUrl}
- Package ID: ${context.packageId}

You have a \`bash\` tool to run shell commands and a \`write_file\` tool to write files (use this for JSON and multi-line content). The contract source is at ./target/ (symlink to the project).
The @mysten/sui v2 TypeScript SDK is available. Use \`npx tsx <file>.mts\` to run TypeScript files.
IMPORTANT: Use \`SuiJsonRpcClient\` from \`@mysten/sui/jsonRpc\` — NOT \`SuiClient\` (which does not exist in v2).
Write your exploit scripts in the current directory.

When you are done, write your findings to findings.json in the current directory.`;

  return {
    stable: `${parts.stable}\n\n${envSection}`,
    dynamic: parts.dynamic,
  };
}

// ── The one assembler ────────────────────────────────────────────

/**
 * Every prompt configuration, as one tagged union. `buildAuditorPrompt`
 * dispatches on `kind`, assembles the shared blocks, and (for the tool-bearing
 * variants) applies the matching env-wrapper.
 */
export type AuditorPromptConfig =
  | {
      kind: "module";
      moduleName: string;
      moduleSource: string;
      packageId: string;
      rpcUrl: string;
      projectInventory?: string;
      network: Network;
      /** Env context for the wrapper; omit to return the unwrapped parts. */
      env?: EnvContext;
    }
  | {
      kind: "entry";
      entryName: string;
      moduleNames: string[];
      packageId: string;
      rpcUrl: string;
      projectInventory?: string;
      network: Network;
      env?: EnvContext;
    }
  | {
      kind: "static-entry";
      entryName: string;
      modules: { name: string; source: string }[];
    }
  | {
      kind: "patch";
      entryName: string;
      moduleNames: string[];
      rootCauses: string[];
      packageId: string;
      rpcUrl: string;
      projectInventory?: string;
      env?: EnvContext;
    }
  | {
      kind: "static-patch";
      entryName: string;
      modules: { name: string; source: string }[];
      rootCauses: string[];
    };

function inventorySection(projectInventory?: string): string {
  return projectInventory ? `\n${projectInventory}\n` : "";
}

/** The module-level auditor prompt: one module inlined, dry-run-only audit. */
function buildModuleParts(
  input: Extract<AuditorPromptConfig, { kind: "module" }>,
): AuditorPromptParts {
  const stable = `${METHODOLOGY}

${FOUNDATIONAL_CONTEXT}

${buildExplorationGuidance("module")}

${REFERENCE_TOOLS_SECTION}

${buildSdkReference(input.network, input.rpcUrl, input.packageId)}

${SUI_PROVER_SECTION}
${inventorySection(input.projectInventory)}`;

  const dynamic = `## Target
Module: ${input.moduleName}
Package ID: ${input.packageId}${input.network === "mainnet" ? `\nRPC: ${input.rpcUrl}` : ""}
Network: ${input.network}

## Source
\`\`\`move
${input.moduleSource}
\`\`\`

${buildOutputFormat(input.moduleName)}`;

  return { stable, dynamic };
}

/** Devnet/mainnet entry-level prompt: whole package, navigated via inventory
 *  + on-demand reads of ./target/. No module source is inlined. */
function buildEntryParts(
  input: Extract<AuditorPromptConfig, { kind: "entry" }>,
): AuditorPromptParts {
  const stable = `${METHODOLOGY}

${FOUNDATIONAL_CONTEXT}

${buildExplorationGuidance("entry")}

${REFERENCE_TOOLS_SECTION}

${buildSdkReference(input.network, input.rpcUrl, input.packageId)}

${SUI_PROVER_SECTION}
${inventorySection(input.projectInventory)}`;

  const moduleList = input.moduleNames.map((m) => `\`${m}\``).join(", ");
  const dynamic = `## Target Package: ${input.entryName}
Package ID: ${input.packageId}${input.network === "mainnet" ? `\nRPC: ${input.rpcUrl}` : ""}
Network: ${input.network}

This package has ${input.moduleNames.length} module(s): ${moduleList}.
There is NO single "target module" — hunt for vulnerabilities ANYWHERE in the package. The full
source is in \`./target/\`. Navigate with the object-capability inventory above and grep/read
\`./target/\` for the specific source you need (per the exploration guidance — do not \`cat\` whole files).

${buildEntryOutputFormat("the module the vulnerability is in", input.network)}`;

  return { stable, dynamic };
}

/** Static (0-harness) entry-level prompt: every module's source inlined, no inventory, no tools. */
function buildStaticEntry(
  input: Extract<AuditorPromptConfig, { kind: "static-entry" }>,
): string {
  const moduleSections = input.modules
    .map((m) => `### Module: ${m.name}\n\`\`\`move\n${m.source}\n\`\`\``)
    .join("\n\n");

  return `You are a smart contract security researcher. Below is the full source of a Sui Move package (${input.modules.length} module(s)). Identify vulnerabilities an unprivileged attacker can exploit for economic gain or to cause permanent, unmitigable damage to other users.

You are doing static analysis only: you cannot deploy, execute, or test anything. Reason from the source. There is no single target module — look for vulnerabilities anywhere in the package.

## Package: ${input.entryName}

${moduleSections}

${ATTACK_CONTEXT_CONTRACT}

${ATTACK_CONTEXT_STATIC_NOTE}

${ATTACK_CTX_SDK}

## Output
Write your findings to findings.json using the write_file tool — a JSON array (use [] if you find nothing):
\`\`\`json
[{
  "id": "unique-id",
  "module": "the module the vulnerability is in",
  "severity": "critical|high|medium|low",
  "title": "Short title",
  "description": "What the bug is, the exploit flow, attacker cost vs damage, and why the victim cannot mitigate it.",
  "exploitScript": "exploit-<id>.mts"
}]
\`\`\``;
}

/** Devnet patch arm: full package in ./target/, execution tooling for iteration. */
function buildPatchParts(
  input: Extract<AuditorPromptConfig, { kind: "patch" }>,
): AuditorPromptParts {
  const stable = `${PATCH_TASK}

${FOUNDATIONAL_CONTEXT}

${buildExplorationGuidance("entry")}

${REFERENCE_TOOLS_SECTION}

${buildSdkReference("devnet", input.rpcUrl, input.packageId)}

${SUI_PROVER_SECTION}
${inventorySection(input.projectInventory)}`;

  const moduleList = input.moduleNames.map((m) => `\`${m}\``).join(", ");
  const dynamic = `## Target Package: ${input.entryName}
Package ID: ${input.packageId}
Network: devnet

This package has ${input.moduleNames.length} module(s): ${moduleList}. The full source is in \`./target/\` (the affected file lives under \`./target/sources/\`).

${buildKnownVulnSection(input.rootCauses)}

${PATCH_DEVNET_NOTE}

${PATCH_OUTPUT_CONTRACT}`;

  return { stable, dynamic };
}

/** Static patch arm: sources inlined, no execution — write the fix blind. */
function buildStaticPatch(
  input: Extract<AuditorPromptConfig, { kind: "static-patch" }>,
): string {
  const moduleSections = input.modules
    .map((m) => `### Source file: ${m.name}\n\`\`\`move\n${m.source}\n\`\`\``)
    .join("\n\n");

  return `${PATCH_TASK}

You are doing static analysis only: you cannot deploy, execute, or test anything. Reason from the source and the known root cause.

## Package: ${input.entryName}

${moduleSections}

${buildKnownVulnSection(input.rootCauses)}

${PATCH_STATIC_NOTE}

${PATCH_OUTPUT_CONTRACT}`;
}

/**
 * The one assembler for the tool-bearing variants (module/entry/patch): builds
 * the split `AuditorPromptParts` and applies the network's env-wrapper.
 */
export function buildAuditorPromptParts(
  config: Extract<AuditorPromptConfig, { kind: "module" | "entry" | "patch" }>,
): AuditorPromptParts {
  switch (config.kind) {
    case "module": {
      const parts = buildModuleParts(config);
      if (!config.env) return parts;
      return config.network === "mainnet"
        ? wrapMainnetEnv(parts, config.env)
        : wrapDevnetEnv(parts, config.env);
    }
    case "entry": {
      const parts = buildEntryParts(config);
      if (!config.env) return parts;
      return config.network === "mainnet"
        ? wrapMainnetEnv(parts, config.env)
        : wrapDevnetEnv(parts, config.env);
    }
    case "patch": {
      const parts = buildPatchParts(config);
      // Patch mode is devnet-only, so it always uses the devnet env-wrapper.
      if (!config.env) return parts;
      return wrapDevnetEnv(parts, config.env);
    }
  }
}

/** The static-arm assembler — plain-string prompts (no env-wrapper, no split). */
export function buildAuditorPromptString(
  config: Extract<AuditorPromptConfig, { kind: "static-entry" | "static-patch" }>,
): string {
  return config.kind === "static-entry"
    ? buildStaticEntry(config)
    : buildStaticPatch(config);
}

/**
 * Unified entry point. Dispatches to the parts- or string-form assembler and
 * returns a flat string in both cases (parts joined `stable\n\ndynamic`, exactly
 * as the agent loop flattens a split system prompt). Callers wanting the split
 * (for cache breakpoints) use `buildAuditorPromptParts` directly.
 */
export function buildAuditorPrompt(config: AuditorPromptConfig): string {
  if (config.kind === "static-entry" || config.kind === "static-patch") {
    return buildAuditorPromptString(config);
  }
  const { stable, dynamic } = buildAuditorPromptParts(config);
  return `${stable}\n\n${dynamic}`;
}
