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
import { execFile } from "node:child_process";
import { promisify } from "node:util";
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

const execFileAsync = promisify(execFile);

// Isolation ceilings for untrusted in-container code; env-overridable per run.
const CONTAINER_LIMITS = {
  memory: process.env.SUIBENCH_MEM ?? "2g",
  cpus: process.env.SUIBENCH_CPUS ?? "2",
  pidsLimit: process.env.SUIBENCH_PIDS ?? "512",
} as const;

export const AUDIT_IMAGE = process.env.SUIBENCH_IMAGE ?? "suibench-auditor";

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** A Docker/host failure that prevented grading, rather than a target command exit. */
export class InfraError extends Error {
  constructor(
    message: string,
    readonly attempts = 1,
  ) {
    super(message);
    this.name = "InfraError";
  }
}

export type DockerErrorKind =
  | "command"
  | "infrastructure"
  | "missing-container"
  | "missing-artifact";

function dockerErrorText(err: unknown): string {
  const value = err as {
    message?: unknown;
    stdout?: unknown;
    stderr?: unknown;
  };
  return [value?.message, value?.stdout, value?.stderr]
    .filter((part): part is string => typeof part === "string")
    .join("\n");
}

export function classifyDockerError(err: unknown): DockerErrorKind {
  const value = err as {
    code?: unknown;
    killed?: unknown;
    signal?: unknown;
  };
  const text = dockerErrorText(err);
  if (
    /could not find the file/i.test(text) ||
    /lstat .*no such file/i.test(text)
  ) {
    return "missing-artifact";
  }
  if (/no such container|container .* is not running/i.test(text)) {
    return "missing-container";
  }
  if (
    typeof value?.code !== "number" ||
    value.killed === true ||
    value.signal ||
    /cannot connect to the docker daemon|error during connect|is the docker daemon running|error response from daemon|no such image|pull access denied|context deadline exceeded|request canceled|tls handshake|i\/o timeout/i.test(
      text,
    )
  ) {
    return "infrastructure";
  }
  return "command";
}

function infraError(operation: string, err: unknown): InfraError {
  return new InfraError(`${operation}: ${dockerErrorText(err) || errMsg(err)}`);
}

// --- Docker primitives -------------------------------------------------------

export interface ContainerStartOptions {
  image?: string;
  /** Env passed into the container (TARGET_CONTRACT, NETWORK, PACKAGE_ID, …). */
  env?: Record<string, string>;
  /** A host dir bind-mounted read-only at /workspace/target-ro. */
  mountDir?: string;
  /** Publish the in-container localnet RPC (9000) to a host port. The confirmer
   *  sets this; when unset (the AUDIT sandbox) the container gets `--network none`. */
  publishRpc?: boolean;
}

export async function startContainer(
  opts: ContainerStartOptions,
): Promise<string> {
  const args = [
    "run",
    "-d",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user",
    "1000:1000",
    "--memory",
    CONTAINER_LIMITS.memory,
    "--cpus",
    CONTAINER_LIMITS.cpus,
    "--pids-limit",
    CONTAINER_LIMITS.pidsLimit,
  ];
  for (const [k, v] of Object.entries(opts.env ?? {})) {
    args.push("-e", `${k}=${v}`);
  }
  if (opts.mountDir) {
    args.push("-v", `${resolve(opts.mountDir)}:/workspace/target-ro:ro`);
  }
  if (opts.publishRpc) {
    args.push("-p", "127.0.0.1::9000");
  } else {
    // AUDIT sandbox: no egress. The localnet is loopback and the build hermetic,
    // so cutting the network blocks the model under test from looking up vulns.
    args.push("--network", "none");
  }
  args.push(opts.image ?? AUDIT_IMAGE);

  try {
    const { stdout } = await execFileAsync("docker", args);
    return stdout.trim();
  } catch (err) {
    throw infraError("docker run", err);
  }
}

/** Build the Move package at `mountDir` in a one-off container (no localnet),
 *  mirroring the entrypoint's `sui move build --build-env testnet`. `ok=false`
 *  iff the build exits non-zero (the patch doesn't compile). */
export async function buildPackage(
  mountDir: string,
  image: string,
): Promise<{ ok: boolean; output: string }> {
  const args = [
    "run",
    "--rm",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user",
    "1000:1000",
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

/** Resolve the host-mapped URL for a container's published localnet RPC (9000). */
export async function getMappedRpcUrl(containerId: string): Promise<string> {
  const { stdout } = await execFileAsync("docker", ["port", containerId, "9000"]);
  const hostPort = stdout.trim().split(":").pop();
  if (!hostPort) {
    throw new Error(
      `could not resolve mapped RPC port for ${containerId.slice(0, 12)}`,
    );
  }
  return `http://127.0.0.1:${hostPort}`;
}

const DEFAULT_READY_TIMEOUT_MS = (() => {
  const raw = process.env.SUIBENCH_READY_TIMEOUT_MS;
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 120_000;
})();

export async function waitForReady(
  containerId: string,
  timeoutMs = DEFAULT_READY_TIMEOUT_MS,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await execFileAsync("docker", [
        "exec",
        containerId,
        "test",
        "-f",
        "/workspace/.ready",
      ]);
      return;
    } catch (err) {
      const kind = classifyDockerError(err);
      if (kind === "missing-container" || kind === "infrastructure") {
        throw infraError("docker readiness probe", err);
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new InfraError(
    `Container ${containerId.slice(0, 12)} not ready after ${timeoutMs / 1000}s`,
  );
}

export async function readContextJson(
  containerId: string,
): Promise<Record<string, string>> {
  try {
    const { stdout } = await execFileAsync("docker", [
      "exec",
      containerId,
      "cat",
      "/workspace/context.json",
    ]);
    return JSON.parse(stdout);
  } catch (err) {
    throw infraError("read container context", err);
  }
}

export async function dockerExec(
  containerId: string,
  command: string,
): Promise<ExecResult> {
  try {
    const { stdout, stderr } = await execFileAsync(
      "docker",
      ["exec", containerId, "bash", "-c", command],
      { maxBuffer: 10 * 1024 * 1024, timeout: 120_000 },
    );
    return { stdout, stderr, exitCode: 0 };
  } catch (err: unknown) {
    const kind = classifyDockerError(err);
    if (kind !== "command") throw infraError("docker exec", err);
    const e = err as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? String(err),
      exitCode: e.code ?? 1,
    };
  }
}

export async function copyIntoContainer(
  containerId: string,
  localPath: string,
  containerPath: string,
): Promise<void> {
  try {
    await execFileAsync("docker", [
      "cp",
      localPath,
      `${containerId}:${containerPath}`,
    ]);
  } catch (err) {
    throw infraError("docker cp into container", err);
  }
}

export async function copyFromContainer(
  containerId: string,
  containerPath: string,
  localPath: string,
): Promise<void> {
  try {
    await execFileAsync("docker", [
      "cp",
      `${containerId}:${containerPath}`,
      localPath,
    ]);
  } catch (err) {
    if (classifyDockerError(err) === "missing-artifact") {
      throw new SandboxFileNotFoundError(containerPath);
    }
    throw infraError("docker cp from container", err);
  }
}

export async function removeContainer(containerId: string): Promise<void> {
  try {
    await execFileAsync("docker", ["rm", "-f", containerId]);
  } catch (err) {
    if (classifyDockerError(err) === "missing-container") return;
    throw infraError("docker rm", err);
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
    await this.manager.removeTrackedContainer(this.containerId);
  }
}

// --- SandboxManager ----------------------------------------------------------

// The ONLY place container cleanup lives (also wired to SIGINT/SIGTERM) — no
// adapter removes a container the manager doesn't know about.
export interface SandboxLifecycle {
  startContainer: typeof startContainer;
  removeContainer: typeof removeContainer;
}

export class SandboxManager {
  private readonly containers = new Map<string, string | undefined>();
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

  track(containerId: string, mountDir?: string): void {
    const prior = this.containers.get(containerId);
    this.containers.set(containerId, mountDir ?? prior);
  }

  forget(containerId: string): void {
    this.containers.delete(containerId);
  }

  list(): string[] {
    return [...this.containers.keys()];
  }

  async startTrackedContainer(
    opts: ContainerStartOptions,
  ): Promise<string> {
    if (this.closing) {
      throw new InfraError("sandbox manager is shutting down");
    }
    let finishStart!: () => void;
    const completion = new Promise<void>((resolve) => {
      finishStart = resolve;
    });
    this.pendingStarts.add(completion);
    try {
      const containerId = await this.lifecycle.startContainer(opts);
      this.track(containerId, opts.mountDir);
      if (this.closing) {
        await this.removeTrackedContainer(containerId);
        throw new InfraError("sandbox manager is shutting down");
      }
      return containerId;
    } finally {
      this.pendingStarts.delete(completion);
      finishStart();
    }
  }

  async removeTrackedContainer(containerId: string): Promise<void> {
    const mountDir = this.containers.get(containerId);
    await this.lifecycle.removeContainer(containerId);
    this.containers.delete(containerId);
    if (mountDir) {
      try {
        rmSync(mountDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
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
        image: AUDIT_IMAGE,
        env: { TARGET_CONTRACT: "target", NETWORK: "devnet", ...env },
        mountDir,
        publishRpc: false,
      });
    } catch (err) {
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

    let failures: unknown[] = [];
    for (let attempt = 0; attempt < 2 && this.containers.size > 0; attempt++) {
      const results = await Promise.allSettled(
        this.list().map((id) => this.removeTrackedContainer(id)),
      );
      failures = results
        .filter((result) => result.status === "rejected")
        .map((result) => result.reason);
    }
    if (this.containers.size > 0) {
      throw new InfraError(
        `failed to remove container(s) ${this.list().join(", ")}: ${failures.map(errMsg).join("; ")}`,
      );
    }
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
