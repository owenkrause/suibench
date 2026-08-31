// Low-level Docker CLI plumbing — everything that shells out to `docker`.
// `sandbox.ts` re-exports the names consumers already import; this module also
// carries the new network/create/start/publish verbs the two-network topology
// (chain-net/attack-net) needs. `hardeningFlags()` is the single source of the
// cap-drop/security/resource flags shared by `run` (startContainer) and `create`
// (createContainer), so the two stop duplicating them.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import {
  SandboxFileNotFoundError,
  type ExecResult,
} from "core";
import { UNTRUSTED_IMAGE } from "./images.js";

const execFileAsync = promisify(execFile);

// Isolation ceilings for untrusted in-container code; env-overridable per run.
export const CONTAINER_LIMITS = {
  memory: process.env.SUIBENCH_MEM ?? "2g",
  cpus: process.env.SUIBENCH_CPUS ?? "2",
  pidsLimit: process.env.SUIBENCH_PIDS ?? "512",
  nofile: process.env.SUIBENCH_NOFILE ?? "1024",
} as const;

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

export function infraError(operation: string, err: unknown): InfraError {
  return new InfraError(`${operation}: ${dockerErrorText(err) || errMsg(err)}`);
}

// --- Docker primitives -------------------------------------------------------

export interface ContainerStartOptions {
  image?: string;
  /** Env passed into the container (TARGET_CONTRACT, NETWORK, PACKAGE_ID, …). */
  env?: Record<string, string>;
  /** A host dir bind-mounted read-only at /workspace/target-ro. */
  mountDir?: string;
}

// Cap/security/resource flags shared by `run` and `create`. NOT --user/-d/--network
// — those are per-caller (run pins uid 1000 on --network none; create lets the image
// or the phase entrypoint decide, and attaches a real network).
export function hardeningFlags(): string[] {
  return [
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--memory",
    CONTAINER_LIMITS.memory,
    "--cpus",
    CONTAINER_LIMITS.cpus,
    "--pids-limit",
    CONTAINER_LIMITS.pidsLimit,
    "--ulimit",
    `nofile=${CONTAINER_LIMITS.nofile}`,
    // Bounds on-disk log growth for every grading container (Docker's default
    // json-file driver otherwise writes container stdout/stderr to host disk
    // unbounded — a noisy or malicious process can fill the host). ~30 MiB max
    // per container (10 MiB/file, 3 files kept) — generous for debugging, not
    // a DoS vector.
    "--log-opt",
    "max-size=10m",
    "--log-opt",
    "max-file=3",
  ];
}

export async function startContainer(
  opts: ContainerStartOptions,
): Promise<string> {
  // --pull=never: use exactly the local, manifest-recorded image; never silently
  // pull a substitute from a registry (the default policy would).
  const args = ["run", "-d", "--pull=never", ...hardeningFlags(), "--user", "1000:1000"];
  for (const [k, v] of Object.entries(opts.env ?? {})) {
    args.push("-e", `${k}=${v}`);
  }
  if (opts.mountDir) {
    args.push("-v", `${resolve(opts.mountDir)}:/workspace/target-ro:ro`);
  }
  // No egress, ever. The localnet is loopback and the build is hermetic, so
  // cutting the network blocks the audit model from looking up vulns AND stops
  // untrusted attack code in the grading container from exfiltrating the
  // groundtruth patch/state. The host drives the localnet via `docker exec`.
  args.push("--network", "none");
  args.push(opts.image ?? UNTRUSTED_IMAGE);

  try {
    const { stdout } = await execFileAsync("docker", args);
    return stdout.trim();
  } catch (err) {
    throw infraError("docker run", err);
  }
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

// --- Network / create-start-publish lifecycle (two-network topology) --------

export async function createNetwork(
  name: string,
  opts: { internal?: boolean } = {},
): Promise<void> {
  // `--internal` alone blocks internet egress but leaves the host's bridge
  // gateway reachable — a container can still dial the host on 0.0.0.0
  // through it. gw-mode-isolated (Docker 28+) drops the gateway from the
  // network entirely, closing that pivot. Real on Linux; a no-op on Docker
  // Desktop, whose VM networking doesn't expose the host the same way.
  //
  // Docker configures IPv4 and IPv6 gateways SEPARATELY, and IPv6 can be
  // enabled daemon-wide — an isolated-IPv4 network would then still carry a
  // v6 gateway as an open pivot. The attack-net has no use for IPv6 (the gate,
  // upstream, and localnet are all v4), so disable it outright: `--ipv6=false`
  // removes the v6 subnet + gateway entirely, closing the family rather than
  // just isolating its gateway (and, unlike gateway_mode_ipv6, never errors on
  // a daemon without IPv6 configured).
  const args = opts.internal
    ? [
        "--internal",
        "--ipv6=false",
        "-o",
        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        name,
      ]
    : [name];
  try {
    await execFileAsync("docker", ["network", "create", ...args]);
  } catch (err) {
    throw infraError("docker network create", err);
  }
}

export async function removeNetwork(name: string): Promise<void> {
  try {
    await execFileAsync("docker", ["network", "rm", name]);
  } catch (err) {
    // Already gone == success; any other failure must surface (reject) so
    // teardownAll's retry/warn actually sees it instead of treating it as done.
    if (/no such network|not found/i.test(dockerErrorText(err))) return;
    throw infraError("docker network rm", err);
  }
}

export interface CreateOptions {
  image: string;
  network?: string;
  env?: Record<string, string>;
  entrypoint?: string[];
  publish?: Array<{ host?: string; hostPort?: number; containerPort: number }>;
  extraArgs?: string[];
}

export async function createContainer(opts: CreateOptions): Promise<string> {
  const args = ["create", "--pull=never", ...hardeningFlags()];
  if (opts.network) args.push("--network", opts.network);
  for (const [k, v] of Object.entries(opts.env ?? {})) args.push("-e", `${k}=${v}`);
  for (const p of opts.publish ?? []) {
    args.push("-p", `${p.host ?? "127.0.0.1"}:${p.hostPort ?? ""}:${p.containerPort}`);
  }
  if (opts.entrypoint) args.push("--entrypoint", opts.entrypoint[0]);
  args.push(...(opts.extraArgs ?? []), opts.image, ...(opts.entrypoint?.slice(1) ?? []));
  try {
    const { stdout } = await execFileAsync("docker", args);
    return stdout.trim();
  } catch (err) {
    throw infraError("docker create", err);
  }
}

export async function startCreated(id: string): Promise<void> {
  try {
    await execFileAsync("docker", ["start", id]);
  } catch (err) {
    throw infraError("docker start", err);
  }
}

export async function connectNetwork(id: string, network: string): Promise<void> {
  try {
    await execFileAsync("docker", ["network", "connect", network, id]);
  } catch (err) {
    throw infraError("docker network connect", err);
  }
}

export async function publishedPort(id: string, containerPort: number): Promise<number> {
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync("docker", ["port", id, String(containerPort)]));
  } catch (err) {
    throw infraError("docker port", err);
  }
  const m = /:(\d+)\s*$/.exec(stdout.trim().split("\n")[0] ?? "");
  if (!m) throw new InfraError(`no published port for ${containerPort} on ${id.slice(0, 12)}`);
  return Number(m[1]);
}

/**
 * Blocks on `docker wait <id>` — resolves with the container's exit code.
 * With `timeoutMs`, races the wait against a deadline: on timeout, force-removes
 * the container and resolves `{ timedOut: true }` rather than throwing — this is
 * a diagnostics signal, not a verdict, so callers decide what a timeout means.
 */
export async function dockerWait(
  id: string,
  opts: { timeoutMs?: number } = {},
): Promise<{ exitCode: number; timedOut: boolean }> {
  const wait = execFileAsync("docker", ["wait", id]).then((r) => ({
    exitCode: Number(r.stdout.trim()),
    timedOut: false,
  }));
  if (opts.timeoutMs === undefined) {
    try {
      return await wait;
    } catch (err) {
      throw infraError("docker wait", err);
    }
  }
  wait.catch(() => {});
  let timer: NodeJS.Timeout;
  const deadline = new Promise<{ exitCode: number; timedOut: boolean }>((r) => {
    timer = setTimeout(() => r({ exitCode: 137, timedOut: true }), opts.timeoutMs);
  });
  try {
    const res = await Promise.race([wait, deadline]);
    if (res.timedOut) {
      try {
        await execFileAsync("docker", ["rm", "-f", id], { timeout: 15_000 });
      } catch {
        /* best-effort reap */
      }
    }
    return res;
  } catch (err) {
    throw infraError("docker wait", err);
  } finally {
    clearTimeout(timer!);
  }
}

/** The container's IP address on `network`, via `docker inspect`. */
export async function containerIp(id: string, network: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync("docker", [
      "inspect",
      "-f",
      `{{(index .NetworkSettings.Networks "${network}").IPAddress}}`,
      id,
    ]);
    const ip = stdout.trim();
    if (!ip) throw new InfraError(`no IP for ${id.slice(0, 12)} on network ${network}`);
    return ip;
  } catch (err) {
    if (err instanceof InfraError) throw err;
    throw infraError("docker inspect", err);
  }
}
