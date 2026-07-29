// The ONE in-container execution primitive (`runner.js <script-file> <entryFn>`):
// runs INSIDE the Confirmer container, imports the script, invokes its
// <entryFn>(ctx) against the localnet (localhost:9000), prints the last tx
// digest. The confirmer sequences it as setup → attack → victim, so a multi-step
// exploit is just more calls. `ctx` carries all three keypairs; each phase picks
// its own signer. The host reads committed state out-of-band after each phase.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

const scriptFile = process.argv[2];
const entryFn = process.argv[3] ?? "attack";
if (!scriptFile) {
  console.error("usage: runner.js <script-file> [entryFn]");
  process.exit(2);
}

const raw = JSON.parse(readFileSync("/workspace/context.json", "utf-8"));
const client = new SuiJsonRpcClient({
  url: "http://127.0.0.1:9000",
  network: "localnet",
});
const kp = (k: string) => Ed25519Keypair.fromSecretKey(k);

// Capture the LAST tx to print its digest — the host waits on that before it
// snapshots (its mapped-RPC view can lag execution).
let lastResult: unknown;
const core = client.core as unknown as {
  signAndExecuteTransaction: (...args: unknown[]) => Promise<unknown>;
  waitForTransaction: (opts: { result: unknown }) => Promise<unknown>;
};
const origSignAndExecute = core.signAndExecuteTransaction.bind(core);
core.signAndExecuteTransaction = async (...args: unknown[]) => {
  const result = await origSignAndExecute(...args);
  lastResult = result;
  return result;
};

function digestOf(result: unknown): string | undefined {
  if (!result || typeof result !== "object") return undefined;
  const r = result as { $kind?: string } & Record<string, unknown>;
  const kind = r.$kind;
  if (!kind) return undefined;
  const inner = r[kind] as { digest?: unknown } | undefined;
  return typeof inner?.digest === "string" ? inner.digest : undefined;
}

const ctx = {
  client,
  packageId: raw.packageId as string,
  attacker: kp(raw.attackerKeyPair),
  admin: kp(raw.adminKeyPair),
  user: kp(raw.userKeyPair),
  attackerAddress: raw.attackerAddress as string,
  adminAddress: raw.adminAddress as string,
  userAddress: raw.userAddress as string,
};

const mod = await import(resolve(process.cwd(), scriptFile));
if (typeof mod[entryFn] !== "function") {
  console.error(`script must export \`async function ${entryFn}(ctx)\``);
  process.exit(3);
}

// victim returns its result (a failed op RETURNS non-success, never throws);
// setup/attack return void. If a phase's tx aborts and the SDK THROWS instead of
// returning, the runner exits non-zero — the host reads that as "phase failed".
// For the ATTACK phase the host treats an (untagged) phase failure as "exploit
// did not land on this variant" (a non-confirmation), so an aborting attack is
// graded, not crashed; only the host's own `infra:`-tagged failures propagate.
const phaseResult = await mod[entryFn](ctx);

if (lastResult !== undefined) {
  await core.waitForTransaction({ result: lastResult });
  const digest = digestOf(lastResult);
  if (digest) console.log(`PHASE_DIGEST=${digest}`); // tx-less phase → no digest
}

// The victim's result is the availability signal — serialize it so the host
// classifies the outcome without a live re-read.
if (phaseResult !== undefined && phaseResult !== null) {
  const serialized = JSON.stringify(phaseResult, (_k, v) =>
    typeof v === "bigint" ? v.toString() : v,
  );
  console.log(`PHASE_RESULT=${serialized}`);
}
console.log("PHASE_OK");
