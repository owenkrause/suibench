// The real `Sandbox` adapter.
//
// `ContainerSandbox` runs a command inside a Docker container started with
// `--network none`: the only thing the model under test may touch is the mounted,
// sanitized source, so it can't look up known vulns. (The networked confirmer is
// a DIFFERENT port — `Confirmer` — which keeps the container's network only to
// publish its localnet RPC.)
//
// `SandboxManager` owns container lifecycle/cleanup: every started container is
// tracked and force-removed on teardown or on SIGINT/SIGTERM.
//
// The low-level Docker CLI plumbing lives in `docker.ts` — import primitives
// from there directly, not from here. This module keeps the higher-level
// pieces: SandboxManager, spawnAudit, materializeMount, buildPackage,
// ContainerSandbox, plus the two-network topology additions
// (createTrackedNetwork, launchGateContainer).
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { UNTRUSTED_IMAGE, GATE_IMAGE, CONFIRMER_IMAGE } from "./images.js";
import { scopeAttackerContext } from "./context.js";
import { resolve, isAbsolute, sep } from "node:path";
import {
  chmodSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import {
  SandboxFileNotFoundError,
  type Sandbox,
  type ExecResult,
  type Mount,
} from "core";
import {
  InfraError,
  classifyDockerError,
  infraError,
  startContainer,
  dockerExec,
  copyIntoContainer,
  copyFromContainer,
  removeContainer,
  createNetwork,
  removeNetwork,
  createContainer,
  startCreated,
  connectNetwork,
  containerIp,
  waitForReady,
  readContextJson,
  publishedPort,
  type ContainerStartOptions,
} from "./docker.js";

const execFileAsync = promisify(execFile);

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Build the Move package at `mountDir` in a one-off container (no localnet),
 *  mirroring the entrypoint's `sui move build --build-env testnet`. Always
 *  built OFFLINE (`--network none`): the framework cache is baked into the
 *  image and packages are self-contained, so a legit build needs no egress —
 *  and the caller is grading an untrusted patch that must never fetch deps.
 *  `ok=false` iff the build exits non-zero (the patch doesn't compile). */
export async function buildPackage(
  mountDir: string,
  image: string,
): Promise<{ ok: boolean; output: string }> {
  const args = [
    "run",
    "--rm",
    "--pull=never",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user",
    "1000:1000",
    "--network",
    "none",
    "-v",
    `${resolve(mountDir)}:/workspace/target-ro:ro`,
    "--entrypoint",
    "sh",
    image,
    "-c",
    "cp -a /workspace/target-ro /workspace/target && cd /workspace/target && sui move build --build-env testnet",
  ];
  try {
    const { stdout, stderr } = await execFileAsync("docker", args, {
      maxBuffer: 10 * 1024 * 1024,
    });
    return { ok: true, output: `${stdout}${stderr}` };
  } catch (err) {
    if (classifyDockerError(err) !== "command") {
      throw infraError("docker build container", err);
    }
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, output: `${e.stdout ?? ""}${e.stderr ?? String(err)}` };
  }
}

/** Materialize a `Mount` (sanitized sources) into a host dir laid out as a Move
 *  package: files carry their in-package relative path (`sources/foo.move`,
 *  `Move.toml`). The returned dir is bind-mountable at /workspace/target-ro. */
export function materializeMount(mount: Mount): string {
  const dir = mkdtempSync(join(tmpdir(), "suibench-mount-"));
  chmodSync(dir, 0o755);
  try {
    for (const file of mount.files) {
      if (!file.path || isAbsolute(file.path)) {
        throw new Error(`invalid mount path "${file.path}"`);
      }
      const dest = resolve(dir, file.path);
      if (!dest.startsWith(`${dir}${sep}`)) {
        throw new Error(`mount path escapes its root: "${file.path}"`);
      }
      mkdirSync(dirname(dest), { recursive: true });
      for (let parent = dirname(dest); parent !== dir; parent = dirname(parent)) {
        chmodSync(parent, 0o755);
      }
      writeFileSync(dest, file.contents);
      chmodSync(dest, 0o644);
    }
    return dir;
  } catch (err) {
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}

// --- ContainerSandbox --------------------------------------------------------

export class ContainerSandbox implements Sandbox {
  constructor(
    readonly containerId: string,
    private readonly manager: SandboxManager,
  ) {}

  async exec(cmd: string): Promise<ExecResult> {
    return dockerExec(this.containerId, cmd);
  }

  async copyOut(path: string): Promise<Buffer> {
    const { readFile } = await import("node:fs/promises");
    const tmp = mkdtempSync(join(tmpdir(), "suibench-out-"));
    const local = join(tmp, "out");
    // `docker cp` needs an absolute container path; write_file/exec run in the
    // /workspace WORKDIR, so resolve a relative path there to stay symmetric.
    const abs = path.startsWith("/") ? path : `/workspace/${path}`;
    try {
      try {
        await copyFromContainer(this.containerId, abs, local);
      } catch (err) {
        const message = errMsg(err);
        if (
          /could not find the file/i.test(message) ||
          /lstat .*no such file/i.test(message)
        ) {
          throw new SandboxFileNotFoundError(path);
        }
        throw err;
      }
      return await readFile(local);
    } finally {
      try {
        rmSync(tmp, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }

  async writeFile(path: string, content: string): Promise<void> {
    const { writeFile } = await import("node:fs/promises");
    const tmp = mkdtempSync(join(tmpdir(), "suibench-in-"));
    const local = join(tmp, "f");
    // `docker cp` needs an absolute container path; write_file paths are relative
    // to the /workspace WORKDIR. No shell — the path can't inject a command.
    const abs = path.startsWith("/") ? path : `/workspace/${path}`;
    try {
      await writeFile(local, content);
      await copyIntoContainer(this.containerId, local, abs);
    } finally {
      try {
        rmSync(tmp, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }

  async teardown(): Promise<void> {
    await this.manager.remove(this.containerId);
  }
}

// --- SandboxManager ----------------------------------------------------------

// The ONLY place Docker-resource cleanup lives (also wired to SIGINT/SIGTERM)
// — no adapter removes a container or network the manager doesn't know about.
export interface SandboxLifecycle {
  startContainer: typeof startContainer;
  removeContainer: typeof removeContainer;
}

type TrackedResource = {
  id: string;
  kind: "container" | "network";
  remove: () => Promise<void>;
};

export class SandboxManager {
  private tracked: TrackedResource[] = [];
  private readonly pendingStarts = new Set<Promise<void>>();
  private cleanupRegistered = false;
  private closing = false;

  constructor(
    private readonly keepContainers = false,
    private readonly lifecycle: SandboxLifecycle = {
      startContainer,
      removeContainer,
    },
  ) {
    this.registerSignalHandlers();
  }

  /** The ONLY way a resource gets tracked. Barrier-guarded so a `create` still
   *  in flight when teardownAll starts can't leak either side of the race: it
   *  either gets torn down the instant it lands (already tracked, closing
   *  flips mid-create) or is refused outright (closing was already true). */
  async track(create: () => Promise<TrackedResource>): Promise<TrackedResource> {
    if (this.closing) {
      throw new InfraError("sandbox manager is shutting down");
    }
    let done!: () => void;
    const p = new Promise<void>((r) => (done = r));
    this.pendingStarts.add(p);
    try {
      const res = await create();
      this.tracked.push(res);
      if (this.closing) {
        await res.remove();
        this.tracked = this.tracked.filter((r) => r !== res);
        throw new InfraError("sandbox manager is shutting down");
      }
      return res;
    } finally {
      this.pendingStarts.delete(p);
      done();
    }
  }

  /** Remove a tracked resource (container or network) by id/name and drop it
   *  from tracking. A no-op if nothing by that id is tracked. */
  async remove(id: string): Promise<void> {
    const res = this.tracked.find((r) => r.id === id);
    if (!res) return;
    await res.remove();
    this.tracked = this.tracked.filter((r) => r !== res);
  }

  list(): string[] {
    return this.tracked.map((r) => r.id);
  }

  private runSeq = 0;

  /** Monotonic per-manager token (`r1`, `r2`, ...) for unique per-run resource
   *  names (network names, etc.) — ASCII only, replaces `process.pid`. */
  nextRunToken(): string {
    return `r${++this.runSeq}`;
  }

  /** Create a Docker network and track it for teardown alongside containers
   *  (chain-net/attack-net don't leak past the run). */
  async createTrackedNetwork(
    name: string,
    opts: { internal?: boolean } = {},
  ): Promise<string> {
    await this.track(async () => {
      await createNetwork(name, opts);
      return { id: name, kind: "network", remove: () => removeNetwork(name) };
    });
    return name;
  }

  async startTrackedContainer(
    opts: ContainerStartOptions,
  ): Promise<string> {
    const { id } = await this.track(async () => {
      const id = await this.lifecycle.startContainer(opts);
      return {
        id,
        kind: "container",
        remove: async () => {
          await this.lifecycle.removeContainer(id);
          if (opts.mountDir) {
            try {
              rmSync(opts.mountDir, { recursive: true, force: true });
            } catch {
              /* best-effort */
            }
          }
        },
      };
    });
    return id;
  }

  /** Boot a `--network none` audit sandbox over a sanitized mount. */
  async spawnAudit(
    mount: Mount,
    env: Record<string, string> = {},
  ): Promise<ContainerSandbox> {
    const mountDir = materializeMount(mount);
    let containerId: string;
    try {
      containerId = await this.startTrackedContainer({
        image: UNTRUSTED_IMAGE,
        env: { TARGET_CONTRACT: "target", NETWORK: "localnet", ...env },
        mountDir,
      });
    } catch (err) {
      // Nothing was tracked (the start itself failed), so the mountDir's
      // cleanup closure never ran — clean it up here.
      try {
        rmSync(mountDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
      throw new InfraError(
        `spawnAudit: failed to start container: ${errMsg(err)}`,
        err instanceof InfraError ? err.attempts : 1,
      );
    }
    return new ContainerSandbox(containerId, this);
  }

  async teardownAll(): Promise<void> {
    if (this.keepContainers) return;
    this.closing = true;
    await Promise.allSettled([...this.pendingStarts]);

    // Containers before networks — docker refuses `network rm` while a
    // container is still attached to it. Order is otherwise independent of
    // creation order since we group by kind.
    for (const kind of ["container", "network"] as const) {
      let remaining = this.tracked.filter((r) => r.kind === kind);
      for (let attempt = 0; attempt < 2 && remaining.length > 0; attempt++) {
        const results = await Promise.allSettled(remaining.map((r) => r.remove()));
        remaining = remaining.filter((_, i) => results[i].status === "rejected");
      }
      for (const r of remaining) {
        console.warn(`teardown ${kind} ${r.id} failed after retries (possible leak)`);
      }
    }
    this.tracked = [];
  }

  private registerSignalHandlers(): void {
    if (this.cleanupRegistered) return;
    this.cleanupRegistered = true;
    for (const [signal, code] of [
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      process.on(signal, () => {
        setTimeout(() => process.exit(code), 10_000).unref();
        this.teardownAll().finally(() => process.exit(code));
      });
    }
  }
}

// --- Gate lifecycle ----------------------------------------------------------

const GATE_DATA_PORT = 9000;

const DEFAULT_GATE_READY_TIMEOUT_MS = (() => {
  const raw = process.env.SUIBENCH_GATE_READY_TIMEOUT_MS;
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 30_000;
})();

async function waitForGateLog(
  containerId: string,
  timeoutMs = DEFAULT_GATE_READY_TIMEOUT_MS,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const { stdout } = await execFileAsync("docker", ["logs", containerId]);
      if (/GATE_READY/.test(stdout)) return;
    } catch (err) {
      throw infraError("docker logs (gate readiness)", err);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new InfraError(
    `Gate ${containerId.slice(0, 12)} not GATE_READY after ${timeoutMs / 1000}s`,
  );
}

export interface LaunchGateOptions {
  network: { attack: string; chain: string };
  upstreamHost: string;
  upstreamPort?: number;
  controlPath?: string;
  image?: string;
  env?: Record<string, string>;
}

/** Launch the gate container: create on attack-net, connect chain-net, start,
 *  wait for GATE_READY, and return its attack-net address — what the phase
 *  (on attack-net only) dials. Tracks the container on create so a failed
 *  connect/start/readiness still gets torn down. */
export async function launchGateContainer(
  manager: SandboxManager,
  opts: LaunchGateOptions,
): Promise<{ id: string; url: string }> {
  const { id } = await manager.track(async () => {
    const id = await createContainer({
      image: opts.image ?? GATE_IMAGE,
      network: opts.network.attack,
      env: {
        UPSTREAM_HOST: opts.upstreamHost,
        ...(opts.upstreamPort ? { UPSTREAM_PORT: String(opts.upstreamPort) } : {}),
        ...(opts.controlPath ? { CONTROL_PATH: opts.controlPath } : {}),
        ...opts.env,
      },
    });
    return { id, kind: "container", remove: () => removeContainer(id) };
  });
  // The container is tracked from `createContainer`; if any post-create step
  // throws, reap it here (and drop it from tracking) so a partial launch doesn't
  // leave a container for the caller's per-run cleanup to miss.
  try {
    await connectNetwork(id, opts.network.chain);
    await startCreated(id);
    await waitForGateLog(id);
    const ip = await containerIp(id, opts.network.attack);
    return { id, url: `http://${ip}:${GATE_DATA_PORT}` };
  } catch (err) {
    await manager.remove(id).catch(() => {});
    throw err;
  }
}

// --- Confirmer lifecycle -------------------------------------------------------

/** Launch the confirmer container: create on chain-net (publishing its localnet
 *  RPC to host-loopback) → cp the target to `/workspace/target-ro` (entrypoint.sh
 *  copies it read-write and test-publishes it from there) → start → wait for
 *  readiness → read its context.json. Returns the RAW context (incl. keypairs) —
 *  callers that hand it to a phase must scope it themselves (see
 *  `provisionPhase`/`scopeAttackerContext`). Tracks the container on create so a
 *  failed cp/start/readiness still gets torn down. */
export async function launchConfirmer(
  manager: SandboxManager,
  opts: { network: string; targetDir: string; env?: Record<string, string> },
): Promise<{ id: string; publishedPort: number; chainIp: string; context: Record<string, string> }> {
  const { id } = await manager.track(async () => {
    const cid = await createContainer({
      image: CONFIRMER_IMAGE,
      network: opts.network,
      publish: [{ containerPort: 9000, host: "127.0.0.1" }],
      env: { TARGET_CONTRACT: "target", NETWORK: "localnet", ...opts.env },
    });
    return { id: cid, kind: "container" as const, remove: () => removeContainer(cid) };
  });
  // Tracked from `createContainer`; reap on any post-create failure (and drop it
  // from tracking) so a partial launch doesn't escape the caller's per-run cleanup.
  try {
    await cpDir(id, opts.targetDir, "/workspace/target-ro");
    await startCreated(id);
    await waitForReady(id);
    const context = await readContextJson(id);
    const port = await publishedPort(id, 9000);
    const chainIp = await containerIp(id, opts.network);
    return { id, publishedPort: port, chainIp, context };
  } catch (err) {
    await manager.remove(id).catch(() => {});
    throw err;
  }
}

// --- Phase provisioning -------------------------------------------------------

/** Write `contents` to a tmp file and `docker cp` it in. `chmodSync 0o644`
 *  before the cp — do NOT rely on the host umask: under a restrictive umask
 *  (e.g. 077) the tmp file lands 0600, `docker cp` preserves the mode, and the
 *  uid-1000 phase runner can't read it (context.json / the attack script). */
async function cpText(id: string, contents: string, containerPath: string): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "suibench-phase-"));
  const local = join(tmp, "f");
  try {
    writeFileSync(local, contents);
    chmodSync(local, 0o644);
    await copyIntoContainer(id, local, containerPath);
  } finally {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
}

/** `docker cp <hostDir>/. <id>:<containerPath>`. `hostDir` is a
 *  `materializeMount` dir whose file modes are already explicit 0644/0755, so
 *  no chmod pass is needed here (unlike `cpText`'s ad hoc tmp file). */
async function cpDir(id: string, hostDir: string, containerPath: string): Promise<void> {
  try {
    await execFileAsync("docker", ["cp", `${resolve(hostDir)}/.`, `${id}:${containerPath}`]);
  } catch (err) {
    throw infraError("docker cp dir into container", err);
  }
}

export interface PhaseOptions {
  network: string;
  gateUrl: string;
  context: Record<string, string>;
  targetDir: string; // host dir with the variant source
  runnerBundle: { runner: string; chainDiscovery: string }; // host paths
  attackScript: { name: string; contents: string };
}

/** Provision the untrusted phase container: create (tracked) → cp payload →
 *  start. Runs as the image's uid-1000 user under --cap-drop=ALL throughout —
 *  no root bootstrap, no gosu, no chown. The cp'd payload lands world-readable
 *  and the runner only reads it; the target goes to /workspace/target-src,
 *  which phase-entry.sh copies into a runner-owned, writable dir. `opts.context`
 *  is the RAW/full context (same shape as the confirmer's context.json) — this
 *  function scopes it via `scopeAttackerContext` itself, so admin/user keys
 *  never reach the phase regardless of what the caller passes in. */
export async function provisionPhase(
  manager: SandboxManager,
  opts: PhaseOptions,
): Promise<{ id: string }> {
  const { id } = await manager.track(async () => {
    const cid = await createContainer({
      image: UNTRUSTED_IMAGE,
      network: opts.network,
      entrypoint: ["/usr/local/bin/phase-entry.sh"],
      env: {
        RUNNER_BASE_URL: opts.gateUrl,
        RUNNER_GRPC_WEB_BINARY: "1",
        ATTACK_SCRIPT: opts.attackScript.name,
      },
      // `--ulimit fsize` (bytes, per POSIX RLIMIT_FSIZE) caps any single file
      // the untrusted attack() can create — a portable backstop against a
      // huge-file disk fill. It's on the phase container only, NOT in
      // hardeningFlags(): the trusted confirmer may legitimately write larger
      // build/localnet artifacts. 256 MiB is generous for a legit exploit
      // (which writes small files) but bounds a hostile one.
      //
      // This does NOT cap the untrusted phase's TOTAL writable-overlay usage
      // (many small files under the cap could still add up) — a size-capped
      // tmpfs at /workspace can't be used here because provisioning `docker
      // cp`s the target/runner/attack-script in before `docker start`, and a
      // tmpfs mounted at start would shadow (hide) that pre-start payload.
      // `--storage-opt size=` would cap the whole overlay but only works on
      // daemons whose storage driver supports pquota (overlay2+xfs) — errors
      // out on a stock ext4 host, so it can't be applied unconditionally here.
      // Mitigate the residual at the deploy level: run the Docker data-root on
      // a dedicated/bounded volume (so a fill can't take the host root down
      // with it, e.g. Postgres/the server), or add `--storage-opt size=` where
      // the host's storage driver supports it.
      extraArgs: ["--ulimit", `fsize=${256 * 1024 * 1024}`],
    });
    return { id: cid, kind: "container" as const, remove: () => removeContainer(cid) };
  });
  // Tracked from `createContainer`; reap on any post-create failure (and drop it
  // from tracking) so a partial launch doesn't escape the caller's per-run cleanup.
  try {
    await cpText(id, scopeAttackerContext(opts.context), "/workspace/context.json");
    await cpText(id, opts.attackScript.contents, `/workspace/${opts.attackScript.name}`);
    await copyIntoContainer(id, opts.runnerBundle.runner, "/workspace/runner.ts");
    await copyIntoContainer(id, opts.runnerBundle.chainDiscovery, "/workspace/chain-discovery.ts");
    await cpDir(id, opts.targetDir, "/workspace/target-src");
    await startCreated(id);
    return { id };
  } catch (err) {
    await manager.remove(id).catch(() => {});
    throw err;
  }
}
