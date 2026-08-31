// The ONE in-container execution primitive (`runner.js <script-file> <entryFn>`):
// runs INSIDE the Confirmer container, imports the script, invokes its
// <entryFn>(ctx) against the localnet (localhost:9000), prints the last tx
// digest. The confirmer sequences it as setup → attack → victim, so a multi-step
// exploit is just more calls. `ctx` carries all three keypairs; each phase picks
// its own signer. The host reads committed state out-of-band after each phase.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { SimulationError } from "@mysten/sui/client";
import { SuiGrpcClient, GrpcWebFetchTransport } from "@mysten/sui/grpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { ChainDiscovery } from "./chain-discovery.js";

const scriptFile = process.argv[2];
const entryFn = process.argv[3] ?? "attack";
if (!scriptFile) {
  console.error("usage: runner.js <script-file> [entryFn]");
  process.exit(2);
}

const raw = JSON.parse(readFileSync("/workspace/context.json", "utf-8"));
// Default path (confirmer): SDK-default transport straight to the loopback RPC.
// The gate spike overrides the target (RUNNER_BASE_URL) and forces binary
// grpc-web (RUNNER_GRPC_WEB_BINARY) — the SDK default is grpc-web-TEXT, which the
// pinned gate rejects — so real submit/read traffic reaches the gate as
// binary/HTTP-1.1 exactly as the pinned client contract requires.
const baseUrl = process.env.RUNNER_BASE_URL ?? "http://127.0.0.1:9000";
const client = process.env.RUNNER_GRPC_WEB_BINARY
  ? new SuiGrpcClient({
      network: "localnet",
      transport: new GrpcWebFetchTransport({ baseUrl, format: "binary" }),
    })
  : new SuiGrpcClient({ baseUrl, network: "localnet" });
const chain = new ChainDiscovery(
  client,
  BigInt(raw.benchmarkStartCheckpoint as string),
);
const kp = (k: string) => Ed25519Keypair.fromSecretKey(k);

// Await the LAST tx before this phase returns, so committed state is visible to
// the host's next snapshot exec (which reads the same in-container localnet).
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

// Least privilege: the `attack` phase runs UNTRUSTED model code, so it is handed
// ONLY the attacker keypair — never admin/user, which would let a malicious
// exploit sign as those roles and fabricate the graded state (or puppet the
// victim) without exploiting the bug. setup/victim are trusted harness scripts
// and keep their keypairs. All three ADDRESSES are public and available to every
// phase.
const trustedPhase = entryFn !== "attack";
const ctx = {
  client,
  chain,
  packageId: raw.packageId as string,
  attacker: kp(raw.attackerKeyPair),
  ...(trustedPhase
    ? { admin: kp(raw.adminKeyPair), user: kp(raw.userKeyPair) }
    : {}),
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
let phaseResult: unknown;
try {
  phaseResult = await mod[entryFn](ctx);
} catch (error) {
  if (
    entryFn === "victim" &&
    error instanceof SimulationError &&
    error.executionError
  ) {
    phaseResult = { status: { success: false, error: error.executionError } };
  } else {
    throw error;
  }
}

if (lastResult !== undefined) {
  await core.waitForTransaction({ result: lastResult });
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
