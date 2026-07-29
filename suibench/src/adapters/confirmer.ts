// `Confirmer` — the networked `Grader`. `pre` is captured HERE (not passed in)
// because only the grader boots the localnet and runs setup, so only it knows
// the post-setup baseline.
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename, resolve, extname } from "node:path";
import { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
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
  EventLog,
} from "core";
import {
  InfraError,
  materializeMount,
  waitForReady,
  getMappedRpcUrl,
  readContextJson,
  copyIntoContainer,
  dockerExec,
} from "./sandbox.js";
import type { SandboxManager } from "./sandbox.js";

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
  const payload =
    r && r.$kind
      ? (r[r.$kind] as {
          status?: { success?: boolean; error?: { message?: string } | null };
        })
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
const RUNNER_SRC = (() => {
  const source = resolve(import.meta.dirname, "runner.ts");
  if (existsSync(source)) return source;
  const sibling = resolve(import.meta.dirname, "runner.js");
  if (existsSync(sibling)) return sibling;
  return resolve(import.meta.dirname, "../../dist/adapters/runner.js");
})();
const RUNNER_NAME = extname(RUNNER_SRC) === ".ts" ? "runner.ts" : "runner.mjs";

const CONFIRMER_IMAGE = process.env.SUIBENCH_IMAGE ?? "suibench-auditor";

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function parsePhaseDigest(stdout: string): string | undefined {
  const m = stdout.match(/^PHASE_DIGEST=(\S+)$/m);
  return m ? m[1] : undefined;
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

/** Content identity of a (mount, script) capture — the base-boot cache key. */
function cacheKey(mount: Mount, script: MoveFile): string {
  const files = [...mount.files]
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((f) => `${f.path}\0${f.contents}`)
    .join("\0");
  return `${script.path}\0${script.contents}\0\0${files}`;
}

interface BootContext {
  client: SuiJsonRpcClient;
  packageId: string;
  addresses: string[];
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
}

// Comprehensive snapshot (balances + objects-with-fields + events) so a
// snapshot-pure check needs no live client.
async function captureSnapshotUnchecked(
  ctx: BootContext,
  eventDigest?: string,
): Promise<ChainSnapshot> {
  const byAddress: Record<string, Record<string, bigint>> = {};
  const ownerOf: Record<string, string | null> = {};
  const byId: Record<string, ObjectState> = {};

  for (const addr of ctx.addresses) {
    const coins = await ctx.client.getAllBalances({ owner: addr });
    const perCoin: Record<string, bigint> = {};
    for (const c of coins) perCoin[c.coinType] = BigInt(c.totalBalance);
    byAddress[addr] = perCoin;

    let cursor: string | null | undefined = null;
    do {
      const page = (await ctx.client.getOwnedObjects({
        owner: addr,
        cursor,
        options: { showContent: true, showType: true, showOwner: true },
      })) as {
        data: Array<{ data?: RawObject }>;
        hasNextPage: boolean;
        nextCursor?: string | null;
      };
      for (const entry of page.data) {
        const parsed = parseObject(entry.data);
        if (parsed) {
          byId[parsed.id] = parsed.state;
          ownerOf[parsed.id] = parsed.state.owner;
        }
      }
      cursor = page.hasNextPage ? page.nextCursor : undefined;
    } while (cursor);
  }

  const events: EventLog["events"] = [];
  if (eventDigest) {
    try {
      const tx = (await ctx.client.getTransactionBlock({
        digest: eventDigest,
        options: { showEvents: true },
      })) as { events?: Array<RawEvent> };
      for (const ev of tx.events ?? []) {
        events.push({
          type: ev.type,
          sender: ev.sender ?? "",
          data: ev.parsedJson ?? null,
        });
      }
    } catch {
      /* events are best-effort; a snapshot without them is still valid */
    }
  }

  const balances: BalanceSet = { byAddress };
  const objects: ObjectSet = { ownerOf, byId };
  const eventLog: EventLog = { events };
  return { balances, objects, events: eventLog };
}

async function captureSnapshot(
  ctx: BootContext,
  eventDigest?: string,
): Promise<ChainSnapshot> {
  try {
    return await captureSnapshotUnchecked(ctx, eventDigest);
  } catch (err) {
    if (err instanceof InfraError) throw err;
    throw new InfraError(`snapshot RPC failed: ${errMsg(err)}`);
  }
}

interface RawObject {
  objectId?: string;
  type?: string;
  owner?: unknown;
  content?: {
    dataType?: string;
    type?: string;
    fields?: Record<string, unknown>;
  };
}

interface RawEvent {
  type: string;
  sender?: string;
  parsedJson?: unknown;
}

/** Normalize an owner descriptor (v2 RPC) to an address, or null for shared/immutable. */
function ownerAddress(owner: unknown): string | null {
  if (owner && typeof owner === "object") {
    const o = owner as Record<string, unknown>;
    if (typeof o.AddressOwner === "string") return o.AddressOwner;
    if (typeof o.ObjectOwner === "string") return o.ObjectOwner;
  }
  return null;
}

function parseObject(
  data: RawObject | undefined,
): { id: string; state: ObjectState } | null {
  if (!data || !data.objectId) return null;
  const content = data.content;
  if (!content || content.dataType !== "moveObject") return null;
  const type = content.type ?? data.type ?? "";
  return {
    id: data.objectId,
    state: {
      owner: ownerAddress(data.owner),
      type,
      fields: content.fields ?? {},
    },
  };
}

interface Phase {
  script: MoveFile;
  entryFn: "setup" | "attack" | "victim";
}

export class Confirmer implements Grader {
  // Opt-in content-keyed cache: the counterfactual re-runs the same base
  // (mount, script) twice, so this boots it once. Patched mounts never hit it.
  private readonly cache = new Map<string, Promise<GraderResult>>();

  constructor(
    private readonly manager: SandboxManager,
    private readonly harness: ConfirmerHarness = {},
    private readonly image = CONFIRMER_IMAGE,
    private readonly reuseBaseBoot = false,
  ) {}

  async runOnMount(mount: Mount, script: MoveFile): Promise<GraderResult> {
    if (!this.reuseBaseBoot) return this.captureFresh(mount, script);
    const key = cacheKey(mount, script);
    let hit = this.cache.get(key);
    if (!hit) {
      hit = this.captureFresh(mount, script);
      this.cache.set(key, hit);
    }
    return hit;
  }

  // Boot a container on `mountDir`, publish (build) the mount, and assemble the
  // BootContext + the in-container runner. Boot/publish failures are infra.
  private async boot(
    mountDir: string,
  ): Promise<{ containerId: string; ctx: BootContext }> {
    let containerId: string | undefined;
    try {
      containerId = await this.manager.startTrackedContainer({
        image: this.image,
        env: { TARGET_CONTRACT: "target", NETWORK: "devnet" },
        mountDir,
        publishRpc: true,
      });
      await waitForReady(containerId);
      const rpcUrl = await getMappedRpcUrl(containerId);
      const client = new SuiJsonRpcClient({ url: rpcUrl, network: "localnet" });
      const raw = await readContextJson(containerId);
      await copyIntoContainer(
        containerId,
        RUNNER_SRC,
        `/workspace/suibench/${RUNNER_NAME}`,
      );
      return {
        containerId,
        ctx: {
          client,
          packageId: raw.packageId,
          attackerAddress: raw.attackerAddress,
          adminAddress: raw.adminAddress,
          userAddress: raw.userAddress,
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
        await this.runPhase(booted.ctx, containerId, {
          script: this.harness.setup,
          entryFn: "setup",
        });
      }
      await this.runPhase(booted.ctx, containerId, {
        script: functional,
        entryFn: "attack",
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

  private async captureFresh(
    mount: Mount,
    script: MoveFile,
  ): Promise<GraderResult> {
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

  private async captureOnMountDir(
    mountDir: string,
    script: MoveFile,
  ): Promise<GraderResult> {
    const { containerId, ctx } = await this.boot(mountDir);
    try {
      // --- phase 1: setup → capture PRE (post-setup baseline) ---
      if (this.harness.setup) {
        await this.runPhase(ctx, containerId!, {
          script: this.harness.setup,
          entryFn: "setup",
        });
      }
      const pre = await captureSnapshot(ctx);

      // --- phase 2: attack (the varied exploit) → capture POST ---
      // An attack that does not land is a NORMAL counterfactual outcome (the
      // "fails under patch" half): the grader still returns evidence — the
      // (unchanged) committed state — and the `Check` reads it as false. Legacy's
      // rule, site-based not string-based: a failure DURING the attack run is the
      // exploit's problem (a non-confirmation), so we swallow it and snapshot;
      // only the confirmer's own `infra:`-tagged failures (boot/publish/host
      // wait) mean "couldn't grade" and propagate.
      let post: ChainSnapshot;
      try {
        const attackOut = await this.runPhase(ctx, containerId!, {
          script,
          entryFn: "attack",
        });
        post = await captureSnapshot(ctx, parsePhaseDigest(attackOut));
      } catch (err) {
        if (err instanceof InfraError) throw err;
        post = await captureSnapshot(ctx);
      }

      // --- phase 3: victim (availability signal) → fold into POST ---
      // Runs whether or not the attack landed: after a non-landing attack the
      // legit op SUCCEEDS (→ check false); after a DoS it aborts/exhausts gas
      // (→ check true). So availability grades correctly on both sides.
      if (this.harness.victim) {
        const victimOut = await this.runPhase(ctx, containerId!, {
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
          packageId: ctx.packageId,
          attackerAddress: ctx.attackerAddress,
          adminAddress: ctx.adminAddress,
          userAddress: ctx.userAddress,
        },
      };
    } finally {
      await this.teardown(containerId);
    }
  }

  // Waits for the host's mapped-RPC view to include the phase's final tx (the
  // coin/object index can lag execution) so the next snapshot is consistent.
  private async runPhase(
    ctx: BootContext,
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

    const digest = parsePhaseDigest(res.stdout);
    if (digest) {
      try {
        await ctx.client.core.waitForTransaction({ digest });
      } catch (err) {
        throw new InfraError(
          `host waitForTransaction(${digest}) failed: ${errMsg(err)}`,
        );
      }
    }
    return res.stdout;
  }

  private async teardown(containerId: string | undefined): Promise<void> {
    if (!containerId) return;
    try {
      await this.manager.removeTrackedContainer(containerId);
    } catch {
      /* retained by the manager for teardownAll's retry */
    }
  }
}
