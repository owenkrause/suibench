// Topology + isolated-confirm integration test (SuiBench untrusted-isolation
// plan, 2A capstone + 2B cutover). Two halves over ONE confirmed-tier entry:
//
//   PART A — MECHANISM (probe attack, no real exploit): stand the whole
//   topology up by hand — chain-net + attack-net, confirmer, gate, phase — and
//   assert:
//     - §9.1 invariant 1: the phase has NO route to the localnet except through
//       the gate (a probe attack tries the confirmer's chain-net IP, its own
//       loopback, and host.docker.internal directly and must fail all three —
//       the last one is the host-pivot gw-mode-isolated closes).
//     - the positive path: a real gRPC read AND a real submit reach the localnet
//       THROUGH the gate, and the gate's drain records the submitted digest.
//     - the confirmer is never attached to attack-net.
//     - attack-net has no IPAM gateway (gw-mode-isolated took effect on the
//       host-side network config, not just observed at runtime).
//     - host-side snapshot gather (captureChainSnapshot) reduces to the same DTO
//       as the in-container gather (snapshot-runner.ts) for the same addresses/
//       checkpoint.
//
//   PART B — END-TO-END: drive that SAME entry's committed reference exploit
//   through `Confirmer.runOnMount` (the production two-network flow) and assert
//   a non-empty `delta` whose witness set (via `runCheck`) contains the
//   reference `vuln.id`. This exercises the real grader sequence (setup ->
//   PRE -> isolated attack -> drain -> host-
//   confirm -> POST -> victim) on a real exploit — the piece Part A's probe does
//   not. runOnMount stands up and tears down its OWN topology; here we only
//   observe the returned evidence.
//
// Run manually (needs Docker + the three suibench-{confirmer,untrusted-runtime,
// gate} images built) — NOT wired to CI. Part A does not touch the production
// grading sequence; Part B runs it directly.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { extname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert/strict";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { normalizeSuiAddress } from "@mysten/sui/utils";
import type { Mount, MoveFile } from "core";
import { runCheck } from "core";
import {
  copyIntoContainer,
  dockerWait,
  dockerExec,
} from "../src/adapters/docker.js";
import {
  SandboxManager,
  materializeMount,
  launchGateContainer,
  launchConfirmer,
  provisionPhase,
} from "../src/adapters/sandbox.js";
import { Confirmer, drainGate, parsePhaseResult } from "../src/adapters/confirmer.js";
import { captureChainSnapshot } from "../src/adapters/snapshot.js";
import { loadEntry, loadSource, loadCheck } from "../src/dataset/index.js";
import type { DrainResult } from "../src/adapters/gate.js";

const execFileAsync = promisify(execFile);
const HERE = import.meta.dirname;
const ADAPTERS = resolve(HERE, "../src/adapters");
const DATASET = resolve(HERE, "../dataset");
const CONTROL_PATH = "/tmp/gate.sock";

// The entry the confirmer publishes. Part A's probe never touches the target
// package, but Part B re-runs this entry's reference exploit through the real
// grader, so it must be a confirmed-tier entry WITH an exploit + check.ts;
// otw_abuse mints an object its check reads, so a landed attack moves the delta
// unambiguously.
const TARGET_ENTRY = "otw_abuse";

// Same source-vs-built resolution confirmer.ts uses (RUNNER_SRC/CHAIN_DISCOVERY_SRC
// etc.): under tsx, copy the TypeScript source and let the container's own tsx
// execute it; in a built install, fall back to the compiled sibling.
function resolveAdapterSrc(baseName: string): string {
  const source = resolve(ADAPTERS, `${baseName}.ts`);
  if (existsSync(source)) return source;
  const sibling = resolve(ADAPTERS, `${baseName}.js`);
  if (existsSync(sibling)) return sibling;
  return resolve(ADAPTERS, `../../dist/adapters/${baseName}.js`);
}
const RUNNER_SRC = resolveAdapterSrc("runner");
const CHAIN_DISCOVERY_SRC = resolveAdapterSrc("chain-discovery");
const SNAPSHOT_SRC = resolveAdapterSrc("snapshot-runner");
const SNAPSHOT_MODULE_SRC = resolveAdapterSrc("snapshot");
// snapshot-runner.ts imports "./snapshot.js" — the copied module must be named
// snapshot.js on disk to resolve that specifier even off the compiled dist
// sibling; only the *runner*'s own on-disk name is free to vary (.ts vs .mjs).
const SNAPSHOT_NAME = extname(SNAPSHOT_SRC) === ".ts" ? "snapshot-runner.ts" : "snapshot-runner.mjs";
const SNAPSHOT_MODULE_NAME = extname(SNAPSHOT_MODULE_SRC) === ".ts" ? "snapshot.ts" : "snapshot.js";
// snapshot.ts itself imports "./chain-discovery.js" — same on-disk-name
// constraint as snapshot.js above.
const CHAIN_DISCOVERY_NAME = extname(CHAIN_DISCOVERY_SRC) === ".ts" ? "chain-discovery.ts" : "chain-discovery.js";

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The probe attack: (a) confirms no direct route to the localnet via a raw TCP
 *  connect classified as `"open" | "refused" | "timeout"` (against the
 *  confirmer's chain-net IP, the phase's own loopback, AND `host.docker.internal`
 *  — the host-pivot gw-mode-isolated is meant to close) — a timeout does NOT
 *  count as proof of isolation, only an explicit refusal (or, for the
 *  unresolvable host alias, a DNS failure) does; (b) a real gRPC read through
 *  ctx.client (gate -> localnet); (c) a real submit through ctx.client (a
 *  trivial attacker self-transfer). ctx.client is already pointed at the gate
 *  (RUNNER_BASE_URL/RUNNER_GRPC_WEB_BINARY, set by provisionPhase) — see
 *  src/adapters/runner.ts. */
function probeAttackScript(confirmerChainIp: string): string {
  return `import { Transaction } from "@mysten/sui/transactions";
import net from "node:net";

function probeTcp(host, port) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const done = (r) => { sock.destroy(); resolve(r); };
    sock.setTimeout(1500);
    sock.once("connect", () => done("open"));
    sock.once("timeout", () => done("timeout"));
    sock.once("error", (e) => {
      // Socket-level "no route" AND DNS-resolution failures are both
      // definitive proof of no reachability — host.docker.internal is
      // unresolvable on an isolated network (EAI_AGAIN/ENOTFOUND/EAI_NONAME),
      // which is as conclusive as an ECONNREFUSED, not an inconclusive timeout.
      const noRoute = [
        "ECONNREFUSED","EHOSTUNREACH","ENETUNREACH","EHOSTDOWN","ECONNRESET",
        "EAI_AGAIN","ENOTFOUND","EAI_NONAME",
      ];
      done(noRoute.includes(e.code) ? "refused" : "timeout");
    });
  });
}

export async function attack(ctx) {
  const chainIpStatus = await probeTcp("${confirmerChainIp}", 9000);
  const loopbackStatus = await probeTcp("127.0.0.1", 9000);
  const hostDockerInternalStatus = await probeTcp("host.docker.internal", 9000);

  const { response } = await ctx.client.ledgerService.getServiceInfo({});
  const chainId = response.chainId;

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [coin] = tx.splitCoins(tx.gas, [1]);
  tx.transferObjects([coin], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  const executed = res.Transaction ?? res.FailedTransaction;
  if (!executed) throw new Error("probe: submit returned neither Transaction nor FailedTransaction");
  if (res.$kind === "FailedTransaction") throw new Error("probe: self-transfer submit failed");

  return { chainIpStatus, loopbackStatus, hostDockerInternalStatus, chainId, digest: executed.digest };
}
`;
}

interface ProbeResult {
  chainIpStatus: string;
  loopbackStatus: string;
  hostDockerInternalStatus: string;
  chainId: string;
  digest: string;
}

/** The full set of networks a container is attached to, keyed by network name. */
async function containerNetworks(id: string): Promise<string[]> {
  const { stdout } = await execFileAsync("docker", [
    "inspect",
    "-f",
    "{{json .NetworkSettings.Networks}}",
    id,
  ]);
  return Object.keys(JSON.parse(stdout));
}

/** `docker inspect -f <fmt> <id>`, stdout trimmed. */
async function inspect(id: string, fmt: string): Promise<string> {
  const { stdout } = await execFileAsync("docker", ["inspect", "-f", fmt, id]);
  return stdout.trim();
}

/** Assert the isolation MECHANISM on a live phase container + its attack-net:
 *  attack-net is `.Internal`, the phase is non-privileged, drops ALL caps, has
 *  no bind mounts, runs non-root, and is attached to attack-net ONLY. Returns the
 *  list of failures (empty = mechanism holds). */
async function assertPhaseMechanism(
  phaseId: string,
  attackNet: string,
): Promise<string[]> {
  const failures: string[] = [];
  const attackNetInternal = await inspect(attackNet, "{{.Internal}}");
  if (attackNetInternal !== "true") {
    failures.push(`attack-net ${attackNet} is not internal (.Internal=${attackNetInternal})`);
  }
  // `--internal` alone still leaves the bridge gateway reachable from inside
  // the network; gw-mode-isolated (see createNetwork) is what actually removes
  // it. Assert the mechanism took: no IPAM gateway on attack-net.
  const attackNetIpam = JSON.parse(
    await inspect(attackNet, "{{json .IPAM.Config}}"),
  ) as Array<{ Gateway?: string }> | null;
  const attackNetGateway = attackNetIpam?.find((c) => c.Gateway)?.Gateway;
  if (attackNetGateway) {
    failures.push(
      `attack-net ${attackNet} still has an IPAM gateway (${attackNetGateway}) — gw-mode-isolated did not take effect, host may be reachable via the gateway`,
    );
  }
  // IPv6 gateways are configured independently of IPv4 (createNetwork disables
  // the whole family). If IPv6 is on, a v6 gateway is an open pivot the v4
  // isolation never closes.
  const attackNetIpv6 = await inspect(attackNet, "{{.EnableIPv6}}");
  if (attackNetIpv6 !== "false") {
    failures.push(
      `attack-net ${attackNet} has IPv6 enabled (.EnableIPv6=${attackNetIpv6}) — a v6 gateway may be reachable; createNetwork must pass --ipv6=false`,
    );
  }
  const phasePrivileged = await inspect(phaseId, "{{.HostConfig.Privileged}}");
  if (phasePrivileged !== "false") {
    failures.push(`phase container is privileged (.HostConfig.Privileged=${phasePrivileged})`);
  }
  const phaseCapDrop = JSON.parse(await inspect(phaseId, "{{json .HostConfig.CapDrop}}")) as string[] | null;
  if (!phaseCapDrop || !phaseCapDrop.includes("ALL")) {
    failures.push(`phase container does not drop all capabilities (.HostConfig.CapDrop=${JSON.stringify(phaseCapDrop)})`);
  }
  const phaseMounts = JSON.parse(await inspect(phaseId, "{{json .Mounts}}")) as unknown[] | null;
  if (phaseMounts && phaseMounts.length > 0) {
    failures.push(`phase container has bind mounts (.Mounts=${JSON.stringify(phaseMounts)})`);
  }
  const phaseUser = await inspect(phaseId, "{{.Config.User}}");
  if (!phaseUser || phaseUser === "root" || phaseUser === "0") {
    failures.push(`phase container does not run as a non-root user (.Config.User=${JSON.stringify(phaseUser)})`);
  }
  const phaseNets = (await containerNetworks(phaseId)).sort();
  const expectedNets = [attackNet].sort();
  if (phaseNets.length !== expectedNets.length || !phaseNets.every((n, i) => n === expectedNets[i])) {
    failures.push(`phase container networks (${JSON.stringify(phaseNets)}) != expected (${JSON.stringify(expectedNets)})`);
  }
  return failures;
}

/** TCP-fail-closed reachability: the probe's direct connects to the confirmer's
 *  chain-net IP and its own loopback must be explicitly `refused` (a timeout is
 *  INCONCLUSIVE, never proof of isolation), and its read+submit THROUGH the gate
 *  must have produced a chainId + digest. Returns the list of failures. */
function assertReachabilityRefused(
  result: ProbeResult,
  confirmerChainIp: string,
): string[] {
  const failures: string[] = [];
  const assertRefused = (label: string, target: string, status: string) => {
    if (status === "refused") return;
    if (status === "open") {
      failures.push(`invariant 1 violated: phase opened a direct TCP route to ${target} (a route exists)`);
    } else {
      failures.push(`invariant 1 INCONCLUSIVE: reachability probe to ${target} timed out — could not prove isolation (${label}=${status})`);
    }
  };
  assertRefused("chainIpStatus", `confirmer chain-net IP (${confirmerChainIp}:9000)`, result.chainIpStatus);
  assertRefused("loopbackStatus", "own loopback (127.0.0.1:9000)", result.loopbackStatus);
  assertRefused("hostDockerInternalStatus", "host.docker.internal:9000 (host-pivot)", result.hostDockerInternalStatus);
  if (!result.chainId) failures.push(`gRPC read through the gate produced no chainId (got ${JSON.stringify(result.chainId)})`);
  if (!result.digest) failures.push(`submit through the gate produced no digest (got ${JSON.stringify(result.digest)})`);
  return failures;
}

// Snapshot DTO shape (matches captureChainSnapshot's return / the in-container
// gather's printed JSON) — untyped beyond what the comparison needs.
interface RawSnapshot {
  balances: Record<string, Record<string, string>>;
  objects: Array<{ objectId: string; type: string; owner: unknown; fields: Record<string, unknown> }>;
}

// The two captures are sequential against a live localnet — the Clock (0x6)
// advances between them, so its `timestamp_ms` is dropped before comparing.
// Object order is otherwise deterministic (same code, same underlying chain
// state), but sort by id defensively so this isn't a flaky ordering
// assumption on top of a real correctness check.
const CLOCK_OBJECT_ID = normalizeSuiAddress("0x6");

function normalizeSnapshot(raw: RawSnapshot): RawSnapshot {
  const objects = raw.objects
    .map((o) => {
      if (normalizeSuiAddress(o.objectId) !== CLOCK_OBJECT_ID) return o;
      const { timestamp_ms: _timestamp_ms, ...rest } = o.fields;
      return { ...o, fields: rest };
    })
    .sort((a, b) => a.objectId.localeCompare(b.objectId));
  return { balances: raw.balances, objects };
}

function snapshotIsNonEmpty(snap: {
  balances: { byAddress: Record<string, unknown> };
  objects: { byId: Record<string, unknown> };
}): boolean {
  return (
    Object.keys(snap.balances.byAddress).length > 0 &&
    Object.keys(snap.objects.byId).length > 0
  );
}

async function main(): Promise<void> {
  const failures: string[] = [];
  const manager = new SandboxManager();
  const chainNet = `t-chain-${process.pid}`;
  const attackNet = `t-attack-${process.pid}`;

  const entry = loadEntry(resolve(DATASET, TARGET_ENTRY));
  if (entry.tier !== "confirmed") {
    throw new Error(`${TARGET_ENTRY} is not confirmed-tier (Part B needs check.ts)`);
  }
  const mountDir = materializeMount(loadSource(entry));

  let confirmerId: string | undefined;
  let gateId: string | undefined;
  let phaseId: string | undefined;

  // --- PART A: mechanism + snapshot parity (probe attack, no real exploit) ----
  try {
    await manager.createTrackedNetwork(chainNet);
    await manager.createTrackedNetwork(attackNet, { internal: true });

    // --- confirmer: create -> cp -> start (entrypoint.sh test-publishes the
    // target at startup, so the target must already be present) ---
    const confirmer = await launchConfirmer(manager, { network: chainNet, targetDir: mountDir });
    confirmerId = confirmer.id;
    const published = confirmer.publishedPort;
    const confirmerChainIp = confirmer.chainIp;
    const raw = confirmer.context;

    // Deploy the snapshot gatherer into the confirmer (mirrors confirmer.ts's
    // boot()) so we can run the in-container half of the parity check later.
    // snapshot.ts imports chain-discovery.js, so that must land too.
    await copyIntoContainer(confirmerId, SNAPSHOT_SRC, `/workspace/suibench/${SNAPSHOT_NAME}`);
    await copyIntoContainer(confirmerId, SNAPSHOT_MODULE_SRC, `/workspace/suibench/${SNAPSHOT_MODULE_NAME}`);
    await copyIntoContainer(confirmerId, CHAIN_DISCOVERY_SRC, `/workspace/suibench/${CHAIN_DISCOVERY_NAME}`);

    // --- gate: attack-net + chain-net, upstream = the confirmer's chain-net IP ---
    const gate = await launchGateContainer(manager, {
      network: { attack: attackNet, chain: chainNet },
      upstreamHost: confirmerChainIp,
      controlPath: CONTROL_PATH,
    });
    gateId = gate.id;

    // --- phase: attack-net only, dials the gate ---
    const phase = await provisionPhase(manager, {
      network: attackNet,
      gateUrl: gate.url,
      context: raw,
      targetDir: mountDir,
      runnerBundle: { runner: RUNNER_SRC, chainDiscovery: CHAIN_DISCOVERY_SRC },
      attackScript: { name: "attack.mts", contents: probeAttackScript(confirmerChainIp) },
    });
    phaseId = phase.id;

    const { exitCode } = await dockerWait(phaseId);
    const { stdout, stderr } = await execFileAsync("docker", ["logs", phaseId]);
    const logs = `${stdout}${stderr}`;

    if (exitCode !== 0) failures.push(`phase container exited ${exitCode}, expected 0. logs:\n${logs.slice(0, 2000)}`);
    if (!/PHASE_OK/.test(logs)) failures.push(`phase did not report PHASE_OK. logs:\n${logs.slice(0, 2000)}`);
    const result = parsePhaseResult(logs) as ProbeResult | undefined;
    if (!result) failures.push(`phase produced no PHASE_RESULT. logs:\n${logs.slice(0, 2000)}`);

    // --- assert the MECHANISM that produces isolation, not just its observed
    // effect (the phase container still exists here; `finally` removes it) ---
    failures.push(...(await assertPhaseMechanism(phaseId, attackNet)));

    // --- drain, then remove the gate BEFORE any host read of the localnet
    // (drain ignores outstanding reads; pulling the gate reaps any lingering
    // attack read before snapshot collection, spec §6.2 step 7) ---
    let drain: DrainResult | undefined;
    if (gateId) {
      drain = await drainGate(gateId, CONTROL_PATH);
      await manager.remove(gateId);
      gateId = undefined;
    }

    // --- invariant 1 + the positive path ---
    if (result) {
      failures.push(...assertReachabilityRefused(result, confirmerChainIp));

      if (!drain) {
        failures.push("gate produced no drain result");
      } else {
        if (drain.kind !== "complete") failures.push(`drain.kind = ${drain.kind}, expected "complete"`);
        if (result.digest && !drain.digests.includes(result.digest)) {
          failures.push(`drain.digests (${JSON.stringify(drain.digests)}) does not contain the submitted digest ${result.digest}`);
        }
      }
    }

    // --- confirmer must never be attached to attack-net ---
    const confirmerNets = await containerNetworks(confirmerId);
    if (confirmerNets.includes(attackNet)) {
      failures.push(`confirmer is attached to attack-net (${confirmerNets.join(", ")})`);
    }

    // --- snapshot parity: host-side gather vs in-container gather ---
    const addrs = [raw.attackerAddress, raw.adminAddress, raw.userAddress];
    const checkpoint = BigInt(raw.benchmarkStartCheckpoint);
    const hostClient = new SuiGrpcClient({ baseUrl: `http://127.0.0.1:${published}`, network: "localnet" });
    const hostSnapshot = (await captureChainSnapshot(hostClient, addrs, checkpoint)) as unknown as RawSnapshot;

    const snapExec = await dockerExec(
      confirmerId,
      `cd /workspace/suibench && ./node_modules/.bin/tsx ${SNAPSHOT_NAME}`,
    );
    if (snapExec.exitCode !== 0) {
      failures.push(`in-container snapshot gather failed (exit ${snapExec.exitCode}): ${(snapExec.stderr || snapExec.stdout).slice(0, 800)}`);
    } else {
      const containerSnapshot = JSON.parse(snapExec.stdout) as RawSnapshot;
      try {
        deepStrictEqual(normalizeSnapshot(hostSnapshot), normalizeSnapshot(containerSnapshot));
      } catch (err) {
        failures.push(`snapshot parity mismatch: ${errMsg(err)}`);
      }
    }

    // Part A collects into `failures`; the verdict is deferred to after Part B.
  } finally {
    // Per-resource removal (NOT teardownAll, which closes the manager) so the
    // SAME manager can drive Part B's runOnMount.
    if (gateId) await manager.remove(gateId).catch(() => {});
    if (phaseId) await manager.remove(phaseId).catch(() => {});
    if (confirmerId) await manager.remove(confirmerId).catch(() => {});
    await manager.remove(chainNet).catch(() => {});
    await manager.remove(attackNet).catch(() => {});
    try {
      rmSync(mountDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }

  // --- PART B: end-to-end runOnMount + check (real reference exploit) ---------
  // runOnMount stands up its OWN two-network topology and tears it down in its
  // finally; here we only observe the returned evidence.
  //
  // KNOWN LIMITATION (isolation is asserted on a twin, not on this path): Part A
  // asserts the isolation MECHANISM on a topology this script builds by hand from
  // the same primitives runOnMount uses (createTrackedNetwork{internal},
  // launchGateContainer, provisionPhase); Part B drives the real runOnMount but
  // can only check its RESULT, because runOnMount tears its containers down before
  // returning. So an isolation regression INSIDE captureOnMountDir (e.g. dropping
  // {internal:true}) would fail neither half — Part A builds its own correct twin,
  // and weakening isolation does not break correctness, so the exploit still
  // confirms. This is accepted: runOnMount does not re-implement isolation, it
  // calls the primitives Part A proves, so such a regression is a code-review
  // catch, not a test catch. Closing it would need a test-only introspection hook
  // on captureOnMountDir (fire the live phase/network ids before teardown) so
  // these same assertions could run against runOnMount's real containers.
  try {
    const vuln = entry.manifest.vulns[0];
    const exploitPath = entry.exploits[vuln?.id ?? ""];
    if (!exploitPath) {
      throw new Error(`${TARGET_ENTRY} has no reference exploit for ${vuln?.id}`);
    }
    const exploitScript: MoveFile = {
      path: `${vuln.id}.mts`,
      contents: readFileSync(exploitPath, "utf-8"),
    };
    const check = await loadCheck(entry);
    const allowedWitnessIds = entry.manifest.vulns.map((v) => v.id);
    if (!allowedWitnessIds.includes(vuln.id)) {
      throw new Error(`${TARGET_ENTRY}: reference vuln id "${vuln.id}" is not in its own manifest witness set`);
    }

    const grader = new Confirmer(manager, entry.harness);
    const mount: Mount = loadSource(entry);
    const { delta, params, evidence } = await grader.runOnMount(mount, exploitScript);

    if (!delta.pre || !delta.post) {
      failures.push("[B] runOnMount returned an empty delta (missing pre/post)");
    } else {
      if (!snapshotIsNonEmpty(delta.pre)) failures.push("[B] delta.pre snapshot is empty (no balances/objects)");
      if (!snapshotIsNonEmpty(delta.post)) failures.push("[B] delta.post snapshot is empty (no balances/objects)");
      if (!params.packageId || !params.attackerAddress) {
        failures.push(`[B] params missing packageId/attackerAddress (${JSON.stringify(params)})`);
      }
      const result = runCheck(check, allowedWitnessIds, delta, params, evidence, `${TARGET_ENTRY}/base`);
      if (!result.witnesses.includes(vuln.id)) {
        failures.push(`[B] reference mechanism was not witnessed — the reference exploit did not confirm through runOnMount (${TARGET_ENTRY}/${vuln.id})`);
      }
    }
  } finally {
    // Both parts done: teardownAll sweeps anything that leaked (Part A removed
    // its own resources; runOnMount removed its own run's).
    await manager.teardownAll();
  }

  if (failures.length > 0) {
    throw new Error(`TOPOLOGY VERIFY FAILED:\n${failures.map((f) => `- ${f}`).join("\n")}`);
  }
  console.log(
    "TOPOLOGY VERIFY OK — [A] mechanism holds (invariant 1, read+submit through the gate, drain recorded the digest, confirmer off attack-net, snapshot parity) AND [B] the reference exploit confirmed end-to-end through runOnMount (non-empty delta, check passed).",
  );
}

// Run only as a script, never at import time — otherwise importing any exported
// helper would fire a full topology standup.
const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(resolve(invokedPath)).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
