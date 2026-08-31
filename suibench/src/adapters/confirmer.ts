// `Confirmer` — the networked `Grader`. `pre` is captured HERE (not passed in)
// because only the grader boots the localnet and runs setup, so only it knows
// the post-setup baseline.
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join, basename, resolve, extname } from "node:path";
import { createRequire } from "node:module";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import type {
  Grader,
  GraderResult,
  Mount,
  MoveFile,
  ChainSnapshot,
  VictimOutcome,
  BalanceSet,
  ObjectSet,
  ObjectState,
  ObjectOwner,
  CheckEvidence,
  AttackTransactionEvidence,
  MoveEventEvidence,
} from "core";
import { ownerAddress } from "core";
import {
  InfraError,
  waitForReady,
  readContextJson,
  copyIntoContainer,
  dockerExec,
  dockerWait,
} from "./docker.js";
import {
  materializeMount,
  launchConfirmer,
  launchGateContainer,
  provisionPhase,
} from "./sandbox.js";
import type { SandboxManager } from "./sandbox.js";
import { captureChainSnapshot } from "./snapshot.js";
import { confirmVisible, type DrainResult } from "./gate.js";
import { CONFIRMER_IMAGE } from "./images.js";

const execFileAsync = promisify(execFile);

export { InfraError };

// Setup/victim phase scripts for one entry (both optional). The dataset layer
// produces this from an entry dir (`loadEntry`); the confirmer only consumes it.
export interface ConfirmerHarness {
  setup?: MoveFile;
  victim?: MoveFile;
}

// A failed tx RETURNS (never throws). The gas_exhausted/abort split matters: an
// entry whose patch turns an infinite loop into a clean abort needs the specific
// `gas_exhausted` status to tell bug from patch.
export function classifyVictimOutcome(result: unknown): VictimOutcome {
  const r = result as { $kind?: string; [k: string]: unknown };
  const payload: {
    status?: { success?: boolean; error?: { message?: string } | null };
  } | undefined =
    r && r.$kind
      ? (r[r.$kind] as {
          status?: { success?: boolean; error?: { message?: string } | null };
        })
      : r && typeof r === "object"
        ? (r as { status?: { success?: boolean; error?: { message?: string } | null } })
        : undefined;
  const status = payload?.status;
  if (status?.success === true) return { status: "success", message: null };
  const message = status?.error?.message ?? null;
  if (message && /InsufficientGas/i.test(message))
    return { status: "gas_exhausted", message };
  if (message && /MoveAbort|abort/i.test(message))
    return { status: "abort", message };
  return { status: "other", message };
}

// Under tsx, copy the TypeScript source and let the container's tsx execute it;
// in a built install, use the sibling JavaScript. The integrity gate therefore
// works from a fresh checkout without relying on an ignored local dist/ tree.
// Bundling-safe fallback: when suibench is bundled into a host app (e.g. the web
// server), import.meta.dirname points at the host's bundle dir, so the ../../dist
// walk-up mis-resolves (doubling `dist`). Resolve suibench's real dist/adapters
// via its own package export instead. Native suibench runs hit the sibling checks
// first and never reach this.
const bundledAdapter = (file: string): string =>
  resolve(createRequire(import.meta.url).resolve("suibench/dataset"), "../../adapters", file);

const RUNNER_SRC = (() => {
  const source = resolve(import.meta.dirname, "runner.ts");
  if (existsSync(source)) return source;
  const sibling = resolve(import.meta.dirname, "runner.js");
  if (existsSync(sibling)) return sibling;
  return bundledAdapter("runner.js");
})();
const RUNNER_NAME = extname(RUNNER_SRC) === ".ts" ? "runner.ts" : "runner.mjs";

const CHAIN_DISCOVERY_SRC = (() => {
  const source = resolve(import.meta.dirname, "chain-discovery.ts");
  if (existsSync(source)) return source;
  const sibling = resolve(import.meta.dirname, "chain-discovery.js");
  if (existsSync(sibling)) return sibling;
  return bundledAdapter("chain-discovery.js");
})();
const CHAIN_DISCOVERY_NAME =
  extname(CHAIN_DISCOVERY_SRC) === ".ts"
    ? "chain-discovery.ts"
    : "chain-discovery.js";

// The gate's control-plane UDS path (matches gate-main.ts's default); the host
// drives /drain over it via `docker exec <gate>`.
const CONTROL_PATH = "/tmp/gate.sock";

// Bound on the untrusted attack phase. A timeout is DIAGNOSTICS ONLY (dev #4) —
// dockerWait reaps the container and returns `timedOut`, never throws.
const PHASE_TIMEOUT_MS = (() => {
  const n = Number(process.env.SUIBENCH_PHASE_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : 120_000;
})();

// Host-side visibility bounds for the drained digests (the ~170ms index lag,
// spec §7.1): each digest gets `perDigest`, the whole batch `overall`.
const VISIBILITY_PER_DIGEST_MS = 5_000;
const VISIBILITY_OVERALL_MS = 30_000;

// Bound on each host-side snapshot RPC call — a stalled localnet must not hang
// the run's `finally` forever (every in-try host call needs a deadline).
const SNAPSHOT_TIMEOUT_MS = 60_000;

// Bound on the whole attack-evidence fetch batch — paired with a real
// Promise.race so a client that ignores the shared AbortController can't hang
// the run (see `collectCheckEvidence`).
const EVIDENCE_TIMEOUT_MS = 30_000;

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Victim-phase only: its serialized result IS the availability signal.
export function parsePhaseResult(stdout: string): unknown {
  const m = stdout.match(/^PHASE_RESULT=(.*)$/m);
  if (!m) return undefined;
  try {
    return JSON.parse(m[1]);
  } catch {
    return undefined;
  }
}

interface BootContext {
  containerId: string;
  packageId: string;
  addresses: string[];
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
  benchmarkStartCheckpoint: string;
}

// Reduce the raw chain data (balances-as-strings + objects-with-fields) into the
// snapshot-pure DTO a `Check` reads — no live client. Shared by the two host-side
// captures below; the reduction is byte-identical to the old in-container path.
// Balances arrive as strings (JSON has no bigint); object fields arrive as
// strings from the RPC.
function reduceRawSnapshot(
  balances: Record<string, Record<string, string>>,
  objects: RawObject[],
): ChainSnapshot {
  const byAddress: Record<string, Record<string, bigint>> = {};
  for (const [addr, coins] of Object.entries(balances)) {
    const perCoin: Record<string, bigint> = {};
    for (const [coinType, amount] of Object.entries(coins)) {
      perCoin[coinType] = BigInt(amount);
    }
    byAddress[addr] = perCoin;
  }

  const ownerOf: Record<string, string | null> = {};
  const byId: Record<string, ObjectState> = {};
  for (const data of objects) {
    const parsed = parseSnapshotObject(data);
    byId[parsed.id] = parsed.state;
    ownerOf[parsed.id] = ownerAddress(parsed.state.owner);
  }

  const outBalances: BalanceSet = { byAddress };
  const outObjects: ObjectSet = { ownerOf, byId };
  return { balances: outBalances, objects: outObjects };
}

// Host-side snapshot gather over the confirmer's published loopback port — the
// container has no egress and never runs the gatherer itself (Task 3). Any host/
// RPC failure is infra: it means the grader couldn't measure, not that the
// exploit didn't land.
async function captureSnapshotHost(
  publishedPort: number,
  raw: Record<string, string>,
): Promise<ChainSnapshot> {
  try {
    const client = new SuiGrpcClient({
      baseUrl: `http://127.0.0.1:${publishedPort}`,
      network: "localnet",
    });
    const addrs = [raw.attackerAddress, raw.adminAddress, raw.userAddress];
    const checkpoint = BigInt(raw.benchmarkStartCheckpoint);
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new InfraError("snapshot RPC timed out after 60s")),
        SNAPSHOT_TIMEOUT_MS,
      );
    });
    let balances: Record<string, Record<string, string>>;
    let objects: RawObject[];
    try {
      ({ balances, objects } = await Promise.race([
        captureChainSnapshot(client, addrs, checkpoint),
        deadline,
      ]));
    } finally {
      clearTimeout(timer);
    }
    return reduceRawSnapshot(balances, objects);
  } catch (err) {
    if (err instanceof InfraError) throw err;
    throw new InfraError(`snapshot RPC failed: ${errMsg(err)}`);
  }
}

// Host-side backstop on the drain exec: the gate's own /drain self-bounds to
// ~30s (drainDeadlineMs) and normally responds first. This is comfortably
// above that so a wedged/OOM'd gate or a stalled docker daemon can't hang
// runOnMount forever and skip its `finally` cleanup.
const DRAIN_EXEC_TIMEOUT_MS = 60_000;

// Drive the gate's /drain over its control-plane UDS via `docker exec`. The
// boundary settles in-flight submits and reports the committed digests; a drain
// failure is infra (the confirmer can't know the committed state).
export async function drainGate(
  gateId: string,
  controlPath: string,
): Promise<DrainResult> {
  const script = `const http=require("http");const r=http.request({socketPath:${JSON.stringify(controlPath)},method:"POST",path:"/drain"},x=>{let b="";x.on("data",c=>b+=c);x.on("end",()=>process.stdout.write(b))});r.end()`;
  try {
    const { stdout } = await execFileAsync(
      "docker",
      ["exec", gateId, "node", "-e", script],
      { timeout: DRAIN_EXEC_TIMEOUT_MS },
    );
    return JSON.parse(stdout) as DrainResult;
  } catch (err) {
    throw new InfraError(`gate drain failed: ${errMsg(err)}`);
  }
}

// A trusted-shape view of the SDK's `getTransaction` response — the
// @mysten/sui@2.22.0 `TransactionResult` discriminated union is Mysten-
// maintained; we no longer re-validate its shape at runtime (design change:
// trust the SDK). A genuinely off-shape response throws a raw TypeError here,
// which is an acceptable, unwrapped failure — not an `InfraError`.
interface TrustedEventEnvelope {
  eventType: string;
  json: unknown;
}
interface TrustedTransactionPayload {
  events?: readonly TrustedEventEnvelope[];
}
type TrustedTransactionResponse =
  | { $kind: "Transaction"; Transaction: TrustedTransactionPayload }
  | { $kind: "FailedTransaction"; FailedTransaction: TrustedTransactionPayload };

// Pure mapper: narrow on `$kind`, derive DTO status, map events to the
// SDK-free `{type, json}` shape in RPC order.
function extractTransactionPayload(
  response: TrustedTransactionResponse,
): { status: "success" | "failure"; events: readonly MoveEventEvidence[] } {
  const payload =
    response.$kind === "Transaction" ? response.Transaction : response.FailedTransaction;
  const events: MoveEventEvidence[] = (payload.events ?? []).map((event) => ({
    type: event.eventType,
    json: event.json,
  }));
  return { status: response.$kind === "Transaction" ? "success" : "failure", events };
}

// Fetch the committed status + events of exactly the supplied digests, in the
// SDK-free `CheckEvidence` shape a `Check` reads. `core` is the trusted
// host-side client's `.core` namespace only — never a full live client into
// the DTO. `Promise.all` over the input array preserves order AND duplicates
// exactly; the shared `AbortController` is paired with a real `Promise.race`
// deadline so a client that ignores abort cannot hang the run. An RPC
// rejection or a deadline timeout becomes an `InfraError`; partial evidence
// is never returned. A malformed SDK response (see `extractTransactionPayload`)
// is not treated as infrastructure failure — we trust the SDK's types.
export async function collectCheckEvidence(
  core: Pick<SuiGrpcClient["core"], "getTransaction">,
  digests: readonly string[],
  timeoutMs: number = EVIDENCE_TIMEOUT_MS,
): Promise<CheckEvidence> {
  if (digests.length === 0) return { attackTransactions: [] };

  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new InfraError(`evidence collection timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
  });

  const fetches: Promise<AttackTransactionEvidence[]> = Promise.all(
    digests.map(async (digest): Promise<AttackTransactionEvidence> => {
      let response: TrustedTransactionResponse;
      try {
        response = (await core.getTransaction({
          digest,
          include: { events: true },
          signal: controller.signal,
        })) as unknown as TrustedTransactionResponse;
      } catch (err) {
        throw new InfraError(`fetch transaction ${digest} failed: ${errMsg(err)}`);
      }
      const { status, events } = extractTransactionPayload(response);
      return { digest, status, events };
    }),
  );
  // Attach a handler to the un-raced promise now — if `deadline` wins the
  // race below, `fetches` may still reject later with nothing else attached,
  // which Node reports as an unhandled rejection.
  fetches.catch(() => {});

  try {
    return { attackTransactions: await Promise.race([fetches, deadline]) };
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}

// Production wiring seam: the confirmer passes the opaque `DrainResult`
// straight through, so it cannot substitute a chain scan or a trusted-phase
// digest list at a second call site. Requires a complete drain, confirms
// exactly `drain.digests` are visible, then fetches evidence for exactly that
// same array — attack-only provenance, structurally.
export async function finalizeAttackEvidence(
  client: SuiGrpcClient,
  drain: DrainResult,
): Promise<CheckEvidence> {
  if (drain.kind !== "complete") {
    throw new InfraError(
      `gate drain ${drain.kind}: commit status unknown (ambiguous=${drain.ambiguous}, rejected=${drain.rejected})`,
    );
  }
  const vis = await confirmVisible(client, drain.digests, {
    perDigestMs: VISIBILITY_PER_DIGEST_MS,
    overallMs: VISIBILITY_OVERALL_MS,
  });
  if (vis.kind !== "complete") {
    throw new InfraError(
      `drained digests not visible after commit (confirmed ${vis.confirmed.length}/${drain.digests.length})`,
    );
  }
  return collectCheckEvidence(client.core, drain.digests);
}

interface RawObject {
  objectId: string;
  type: string;
  owner: unknown;
  fields: Record<string, unknown>;
}

function parseOwner(owner: unknown): ObjectOwner {
  if (!owner || typeof owner !== "object") {
    throw new Error("snapshot object has no native owner");
  }
  const value = owner as Record<string, unknown>;
  switch (value.$kind) {
    case "AddressOwner":
      return { AddressOwner: String(value.AddressOwner) };
    case "ObjectOwner":
      return { ObjectOwner: String(value.ObjectOwner) };
    case "Shared": {
      const shared = value.Shared as Record<string, unknown>;
      return {
        Shared: { initial_shared_version: String(shared.initialSharedVersion) },
      };
    }
    case "Immutable":
      return "Immutable";
    case "ConsensusAddressOwner": {
      const consensus = value.ConsensusAddressOwner as Record<string, unknown>;
      return {
        ConsensusAddressOwner: {
          start_version: String(consensus.startVersion),
          owner: String(consensus.owner),
        },
      };
    }
    default:
      throw new Error(`unknown native object owner: ${String(value.$kind)}`);
  }
}

export function parseSnapshotObject(
  data: RawObject,
): { id: string; state: ObjectState } {
  if (!data.objectId || !data.type || !data.fields) {
    throw new Error("invalid native snapshot object");
  }
  return {
    id: data.objectId,
    state: {
      owner: parseOwner(data.owner),
      type: data.type,
      fields: data.fields,
    },
  };
}

interface Phase {
  script: MoveFile;
  // Trusted phases only — run via `runPhase` (docker exec) in the confirmer
  // container. The untrusted `attack` never uses this path; it runs isolated in
  // its own phase container via `runAttackPhase` (see above).
  entryFn: "setup" | "victim" | "functional";
}

export class Confirmer implements Grader {
  constructor(
    private readonly manager: SandboxManager,
    private readonly harness: ConfirmerHarness = {},
  ) {}

  async runOnMount(mount: Mount, script: MoveFile): Promise<GraderResult> {
    const mountDir = materializeMount(mount);
    try {
      return await this.captureOnMountDir(mountDir, script);
    } finally {
      try {
        rmSync(mountDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }

  // Single-container boot on `mountDir`: publish (build) the mount and copy in
  // the trusted runner. ONLY `runFunctional` (patch-mode) uses this path — the
  // exploitation grader (`captureOnMountDir`) uses the two-network isolated flow.
  // Boot/publish failures are infra.
  private async boot(
    mountDir: string,
  ): Promise<{ containerId: string; ctx: BootContext }> {
    let containerId: string | undefined;
    try {
      containerId = await this.manager.startTrackedContainer({
        image: CONFIRMER_IMAGE,
        env: { TARGET_CONTRACT: "target", NETWORK: "localnet" },
        mountDir,
        // The container boots `--network none` (no egress); the host drives the
        // localnet only via `docker exec` (the runner), so untrusted code can
        // neither exfiltrate the groundtruth patch/state nor reach off-box.
      });
      await waitForReady(containerId);
      const raw = await readContextJson(containerId);
      await copyIntoContainer(
        containerId,
        RUNNER_SRC,
        `/workspace/suibench/${RUNNER_NAME}`,
      );
      await copyIntoContainer(
        containerId,
        CHAIN_DISCOVERY_SRC,
        `/workspace/suibench/${CHAIN_DISCOVERY_NAME}`,
      );
      return {
        containerId,
        ctx: {
          containerId,
          packageId: raw.packageId,
          attackerAddress: raw.attackerAddress,
          adminAddress: raw.adminAddress,
          userAddress: raw.userAddress,
          benchmarkStartCheckpoint: raw.benchmarkStartCheckpoint,
          addresses: [raw.attackerAddress, raw.adminAddress, raw.userAddress],
        },
      };
    } catch (err) {
      await this.teardown(containerId);
      throw new InfraError(errMsg(err));
    }
  }

  /** Patch-mode: boot the mount, run setup, then `functional` as a MUST-SUCCEED
   *  phase. `passed` iff it reached PHASE_OK — an aborting legit tx throws →
   *  non-PHASE_OK → passed=false. Boot/publish failures (InfraError) propagate. */
  async runFunctional(
    mount: Mount,
    functional: MoveFile,
  ): Promise<{ passed: boolean; error?: string }> {
    const mountDir = materializeMount(mount);
    let containerId: string | undefined;
    try {
      const booted = await this.boot(mountDir);
      containerId = booted.containerId;
      if (this.harness.setup) {
        await this.runPhase(containerId, {
          script: this.harness.setup,
          entryFn: "setup",
        });
      }
      await this.runPhase(containerId, {
        script: functional,
        entryFn: "functional",
      });
      return { passed: true };
    } catch (err) {
      if (err instanceof InfraError) throw err;
      return { passed: false, error: errMsg(err) };
    } finally {
      await this.teardown(containerId);
      try {
        rmSync(mountDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }

  // The exploitation grader — the isolated two-network flow (spec §6.2). The
  // untrusted attack runs in its OWN phase container on an internal attack-net,
  // reaching the localnet ONLY through the gate; the trusted confirmer (localnet,
  // target, setup, victim, snapshot) stays on chain-net and is never attached to
  // attack-net. `verify-topology.ts` is the proven template for this sequence.
  private async captureOnMountDir(
    mountDir: string,
    script: MoveFile,
  ): Promise<GraderResult> {
    // Per-run-unique names — the grader shares ONE manager across concurrent
    // runs, so `process.pid` would collide. `nextRunToken()` is monotonic.
    const token = this.manager.nextRunToken();
    const chainNet = `c-chain-${token}`;
    const attackNet = `c-attack-${token}`;

    let confirmerId: string | undefined;
    let gateId: string | undefined;
    let phaseId: string | undefined;
    try {
      // --- 1: two networks (attack-net internal — no route off it except the gate) ---
      await this.manager.createTrackedNetwork(chainNet);
      await this.manager.createTrackedNetwork(attackNet, { internal: true });

      // --- 2: confirmer on chain-net (publishes its localnet RPC to host loopback) ---
      const confirmer = await launchConfirmer(this.manager, {
        network: chainNet,
        targetDir: mountDir,
      });
      confirmerId = confirmer.id;
      const { publishedPort, chainIp, context: raw } = confirmer;

      // The trusted setup/victim run IN the confirmer container via `runPhase`
      // (docker exec) — copy the runner in for them. The UNTRUSTED attack never
      // runs here; it goes to the isolated phase container (step 5).
      await copyIntoContainer(confirmerId, RUNNER_SRC, `/workspace/suibench/${RUNNER_NAME}`);
      await copyIntoContainer(confirmerId, CHAIN_DISCOVERY_SRC, `/workspace/suibench/${CHAIN_DISCOVERY_NAME}`);

      // --- 3: gate on attack-net + chain-net, upstream = the confirmer's chain IP ---
      const gate = await launchGateContainer(this.manager, {
        network: { attack: attackNet, chain: chainNet },
        upstreamHost: chainIp,
        controlPath: CONTROL_PATH,
      });
      gateId = gate.id;

      // --- 4: trusted setup → PRE (post-setup baseline), host-side ---
      if (this.harness.setup) {
        await this.runPhase(confirmerId, {
          script: this.harness.setup,
          entryFn: "setup",
        });
      }
      const pre = await captureSnapshotHost(publishedPort, raw);

      // --- 5–6: the untrusted attack in its isolated phase container, bounded ---
      // An attack error / non-zero exit / timeout is DIAGNOSTICS ONLY (dev #4):
      // it never throws and never short-circuits — drain, host-confirm, POST, and
      // victim STILL run. A non-landing attack is the NORMAL "fails under patch"
      // counterfactual; the Check reads the unchanged committed state as false.
      phaseId = await this.runAttackPhase({
        attackNet,
        gateUrl: gate.url,
        context: raw,
        targetDir: mountDir,
        script,
        onProvisioned: (id) => {
          phaseId = id;
        },
      });

      // --- 7: drain the gate, remove it BEFORE any host read of the localnet
      // (reaps lingering attack reads, spec §6.2 step 7), then host-confirm the
      // drained digests are locally visible and fetch their committed evidence
      // (`finalizeAttackEvidence` — exactly the drained digests, never a chain
      // scan) before POST. Only host infra (ambiguous/timeout drain, unindexed
      // digest, malformed transaction response) propagates. ---
      const drain = await drainGate(gateId, CONTROL_PATH);
      await this.manager.remove(gateId);
      gateId = undefined;
      const client = new SuiGrpcClient({
        baseUrl: `http://127.0.0.1:${publishedPort}`,
        network: "localnet",
      });
      const evidence = await finalizeAttackEvidence(client, drain);

      // --- 8: POST (committed state after the attack), host-side ---
      let post = await captureSnapshotHost(publishedPort, raw);

      // --- 9: trusted victim (availability signal) → fold into POST ---
      // Runs whether or not the attack landed: after a non-landing attack the
      // legit op SUCCEEDS (→ check false); after a DoS it aborts/exhausts gas
      // (→ check true). So availability grades correctly on both sides.
      if (this.harness.victim) {
        const victimOut = await this.runPhase(confirmerId, {
          script: this.harness.victim,
          entryFn: "victim",
        });
        const victim: VictimOutcome = classifyVictimOutcome(
          parsePhaseResult(victimOut),
        );
        post = { ...post, victim };
      }

      // The params ride WITH the delta: each variant published fresh, so the
      // snapshot-pure Check's packageId + funded addresses are known only here.
      return {
        delta: { pre, post },
        params: {
          packageId: raw.packageId,
          attackerAddress: raw.attackerAddress,
          adminAddress: raw.adminAddress,
          userAddress: raw.userAddress,
        },
        evidence,
      };
    } finally {
      // --- per-run cleanup: THIS run's resources only, containers before
      // networks (docker refuses `network rm` while a container is attached).
      // NEVER teardownAll() — the manager is shared across concurrent runs and
      // that would brick them. `remove` is idempotent (gate already gone). ---
      if (phaseId) await this.manager.remove(phaseId).catch(() => {});
      if (gateId) await this.manager.remove(gateId).catch(() => {});
      if (confirmerId) await this.manager.remove(confirmerId).catch(() => {});
      await this.manager.remove(chainNet).catch(() => {});
      await this.manager.remove(attackNet).catch(() => {});
    }
  }

  // The UNTRUSTED attack: provision an isolated phase container on attack-net
  // (reaches the localnet only through the gate), wait bounded, and return its
  // id. `provisionPhase` scopes the raw context (drops admin/user keypairs)
  // internally — pass it RAW. A non-zero exit / timeout is DIAGNOSTICS ONLY and
  // never throws (dev #4); only provisioning (docker) failures propagate as
  // infra. The phase's own PHASE_OK/exit is read for diagnostics but never grades.
  private async runAttackPhase(opts: {
    attackNet: string;
    gateUrl: string;
    context: Record<string, string>;
    targetDir: string;
    script: MoveFile;
    onProvisioned?: (id: string) => void;
  }): Promise<string> {
    const name = basename(opts.script.path) || "attack.mts";
    const { id } = await provisionPhase(this.manager, {
      network: opts.attackNet,
      gateUrl: opts.gateUrl,
      context: opts.context,
      targetDir: opts.targetDir,
      runnerBundle: { runner: RUNNER_SRC, chainDiscovery: CHAIN_DISCOVERY_SRC },
      attackScript: { name, contents: opts.script.contents },
    });
    opts.onProvisioned?.(id);
    const { exitCode, timedOut } = await dockerWait(id, { timeoutMs: PHASE_TIMEOUT_MS });
    if (process.env.SUIBENCH_DEBUG) {
      const logs = timedOut
        ? ""
        : await execFileAsync("docker", ["logs", id])
            .then((r) => `${r.stdout}${r.stderr}`)
            .catch(() => "");
      console.warn(
        `[confirmer] attack phase ${id.slice(0, 12)}: exit=${exitCode} timedOut=${timedOut} phaseOk=${/PHASE_OK/.test(logs)}`,
      );
    }
    return id;
  }

  // Runs one phase's script in-container via `docker exec` (the runner awaits its
  // own final tx before returning, so committed state is visible to the next
  // snapshot exec without a host-side wait). Used for the TRUSTED setup/victim in
  // the confirmer container — never the attack (which runs isolated, see above).
  private async runPhase(
    containerId: string,
    phase: Phase,
  ): Promise<string> {
    const scriptTmp = mkdtempSync(join(tmpdir(), "suibench-script-"));
    const inName = basename(phase.script.path) || `${phase.entryFn}.mts`;
    const scriptPath = join(scriptTmp, inName);
    writeFileSync(scriptPath, phase.script.contents);
    try {
      await copyIntoContainer(
        containerId,
        scriptPath,
        `/workspace/suibench/${inName}`,
      );
    } finally {
      try {
        rmSync(scriptTmp, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }

    // /workspace/suibench carries "type":"module" (ESM for the runner's
    // top-level await) + the deployed tsx binary.
    const res = await dockerExec(
      containerId,
      `cd /workspace/suibench && ./node_modules/.bin/tsx ${RUNNER_NAME} ${inName} ${phase.entryFn}`,
    );
    if (res.exitCode !== 0 || !res.stdout.includes("PHASE_OK")) {
      throw new Error(
        `${phase.entryFn} phase failed (exit ${res.exitCode}): ${(res.stderr || res.stdout || "").trim().slice(0, 800)}`,
      );
    }

    return res.stdout;
  }

  private async teardown(containerId: string | undefined): Promise<void> {
    if (!containerId) return;
    try {
      await this.manager.remove(containerId);
    } catch {
      /* retained by the manager for teardownAll's retry */
    }
  }
}
