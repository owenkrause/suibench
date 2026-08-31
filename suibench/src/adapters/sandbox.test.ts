// SandboxManager bookkeeping — the Docker-free lifecycle logic (subsumes the legacy
// ResourceTracker). The docker-shelling paths (spawnAudit/teardownAll removal)
// are covered by the real end-to-end; here we assert the tracked-set semantics
// and that keepContainers suppresses teardown, without invoking docker.
//
// launchGateContainer's argv construction/call order IS covered here (mocked
// execFile, same technique as docker.test.ts) — its GATE_READY log-polling and
// containerIp resolution are exercised for real by a later integration test.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { sanitize } from "core";

const state = vi.hoisted(() => ({
  calls: [] as string[][],
  queue: [] as Array<{ stdout?: string; err?: unknown }>,
}));

vi.mock("node:child_process", () => {
  const PROMISIFY_CUSTOM = Symbol.for("nodejs.util.promisify.custom");
  const execFile = (() => {
    throw new Error("callback form of execFile is not exercised by these tests");
  }) as unknown as typeof import("node:child_process").execFile;
  (execFile as unknown as Record<symbol, unknown>)[PROMISIFY_CUSTOM] = async (
    _cmd: string,
    args: string[],
  ) => {
    state.calls.push(args);
    const next = state.queue.shift();
    if (next?.err) throw next.err;
    return { stdout: next?.stdout ?? "", stderr: "" };
  };
  return { execFile };
});

function stubDocker(stdouts: string[]): string[][] {
  state.calls = [];
  state.queue = stdouts.map((stdout) => ({ stdout }));
  return state.calls;
}

beforeEach(() => {
  state.calls = [];
  state.queue = [];
});

import { classifyDockerError, CONTAINER_LIMITS } from "./docker.js";
import {
  materializeMount,
  SandboxManager,
  launchGateContainer,
  provisionPhase,
} from "./sandbox.js";
import { rmSync, statSync } from "node:fs";
import { join } from "node:path";

describe("SandboxManager", () => {
  it("track() records a resource; remove() drops it and calls its cleanup", async () => {
    const manager = new SandboxManager();
    const removed: string[] = [];
    await manager.track(async () => ({
      id: "a",
      kind: "network",
      remove: async () => {
        removed.push("a");
      },
    }));
    await manager.track(async () => ({
      id: "b",
      kind: "network",
      remove: async () => {
        removed.push("b");
      },
    }));
    expect(manager.list().sort()).toEqual(["a", "b"]);
    await manager.remove("a");
    expect(manager.list()).toEqual(["b"]);
    expect(removed).toEqual(["a"]);
  });

  it("teardownAll is a no-op (no removal) when keepContainers=true", async () => {
    const manager = new SandboxManager(true);
    let removeCalled = false;
    await manager.track(async () => ({
      id: "a",
      kind: "network",
      remove: async () => {
        removeCalled = true;
      },
    }));
    await manager.teardownAll(); // must NOT call remove(); ids stay tracked
    expect(manager.list()).toEqual(["a"]);
    expect(removeCalled).toBe(false);
  });

  it("waits for an in-progress container start before teardown completes", async () => {
    let releaseStart!: () => void;
    const startGate = new Promise<void>((resolve) => {
      releaseStart = resolve;
    });
    const removed: string[] = [];
    const manager = new SandboxManager(false, {
      async startContainer() {
        await startGate;
        return "late-container";
      },
      async removeContainer(containerId) {
        removed.push(containerId);
      },
    });

    const spawning = manager.startTrackedContainer({ image: "test-image" });
    await Promise.resolve();
    const teardown = manager.teardownAll();
    releaseStart();

    await expect(spawning).rejects.toThrow(/shutting down/);
    await teardown;
    expect(removed).toEqual(["late-container"]);
    expect(manager.list()).toEqual([]);
  });

  // P1 regression: createTrackedNetwork/launchGateContainer used to create-then-track
  // OUTSIDE the pendingStarts/closing barrier, so a teardown racing a still-in-flight
  // create would leak the resource. Every create now goes through `track()`, which is
  // the only place resources get tracked — assert directly, not just via
  // startTrackedContainer, that a create still in flight when teardownAll starts gets
  // torn down and never sits in `tracked` afterward.
  it("a create still in flight when teardownAll starts is torn down, not leaked", async () => {
    let releaseCreate!: () => void;
    const createGate = new Promise<void>((resolve) => {
      releaseCreate = resolve;
    });
    let removeCalled = false;
    const manager = new SandboxManager();

    const tracking = manager.track(async () => {
      await createGate;
      return {
        id: "late-resource",
        kind: "network" as const,
        remove: async () => {
          removeCalled = true;
        },
      };
    });
    await Promise.resolve();
    const teardown = manager.teardownAll();
    releaseCreate();

    await expect(tracking).rejects.toThrow(/shutting down/);
    await teardown;
    expect(removeCalled).toBe(true);
    expect(manager.list()).toEqual([]);
  });

  it("retries a transient resource-removal failure during teardown", async () => {
    let attempts = 0;
    const manager = new SandboxManager();
    await manager.track(async () => ({
      id: "retry-container",
      kind: "container",
      remove: async () => {
        attempts++;
        if (attempts === 1) throw new Error("temporary Docker failure");
      },
    }));

    await manager.teardownAll();

    expect(attempts).toBe(2);
    expect(manager.list()).toEqual([]);
  });

  // P2 regression: removeNetwork used to swallow every failure into a
  // console.warn and always resolve, so teardownAll's retry loop saw an
  // instant "success" and its own "possible leak" warn never fired for a
  // genuinely-failing network removal — silent success on a real leak. Drives
  // this through the real `createTrackedNetwork`/`removeNetwork` (mocked
  // docker), not a synthetic TrackedResource, to prove the two fixes compose.
  it("teardownAll surfaces a persistent network-removal failure (not swallowed)", async () => {
    const manager = new SandboxManager();
    stubDocker([""]); // `docker network create` succeeds
    await manager.createTrackedNetwork("t-attack-net");

    // Both teardown retry attempts hit a real (non "no such network") failure.
    state.queue = [
      { err: new Error("Error response from daemon: network t-attack-net has active endpoints") },
      { err: new Error("Error response from daemon: network t-attack-net has active endpoints") },
    ];
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    await manager.teardownAll();

    expect(warn).toHaveBeenCalledWith(expect.stringContaining("t-attack-net"));
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("failed after retries"));
    warn.mockRestore();
    expect(manager.list()).toEqual([]);
  });
});

describe("classifyDockerError", () => {
  it("separates command exits from Docker infrastructure failures", () => {
    expect(classifyDockerError({
      code: 1,
      stderr: "MoveAbort in challenge::vault",
    })).toBe("command");
    expect(classifyDockerError({
      code: 1,
      stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    })).toBe("infrastructure");
    expect(classifyDockerError({ code: "ENOENT" })).toBe("infrastructure");
  });

  it("recognizes missing containers and missing copied artifacts", () => {
    expect(classifyDockerError({
      code: 1,
      stderr: "Error response from daemon: No such container: deadbeef",
    })).toBe("missing-container");
    expect(classifyDockerError({
      code: 1,
      stderr: "Could not find the file /workspace/findings.json in container",
    })).toBe("missing-artifact");
  });
});

describe("materializeMount", () => {
  it("makes the mount traversable by the fixed container uid", () => {
    const dir = materializeMount(
      sanitize([{
        path: "sources/example.move",
        contents: "module challenge::example {}",
      }]),
    );
    try {
      expect(statSync(dir).mode & 0o777).toBe(0o755);
      expect(statSync(join(dir, "sources")).mode & 0o777).toBe(0o755);
      expect(statSync(join(dir, "sources/example.move")).mode & 0o777).toBe(0o644);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("normalizes every directory under a restrictive host umask", () => {
    const previousUmask = process.umask(0o077);
    const dir = (() => {
      try {
        return materializeMount(
          sanitize([{
            path: "nested/sources/example.move",
            contents: "module challenge::example {}",
          }]),
        );
      } finally {
        process.umask(previousUmask);
      }
    })();
    try {
      expect(statSync(join(dir, "nested")).mode & 0o777).toBe(0o755);
      expect(statSync(join(dir, "nested/sources")).mode & 0o777).toBe(0o755);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a path that would escape the temporary mount root", () => {
    expect(() =>
      materializeMount(
        sanitize([{ path: "../outside.move", contents: "module outside {}" }]),
      ),
    ).toThrow(/escapes its root/);
  });

  it("rejects absolute paths", () => {
    expect(() =>
      materializeMount(
        sanitize([{ path: "/tmp/outside.move", contents: "module outside {}" }]),
      ),
    ).toThrow(/invalid mount path/);
  });
});

describe("launchGateContainer", () => {
  it("creates on attack-net, connects chain-net, starts, then resolves the attack-net URL", async () => {
    const calls = stubDocker([
      "gate123\n",           // docker create
      "",                    // docker network connect
      "",                    // docker start
      "GATE_READY data=9000\n", // docker logs (first poll)
      "172.30.0.5\n",        // docker inspect
    ]);
    const manager = new SandboxManager();

    const { id, url } = await launchGateContainer(manager, {
      network: { attack: "attack-net", chain: "chain-net" },
      upstreamHost: "10.0.0.9",
    });

    expect(id).toBe("gate123");
    expect(url).toBe("http://172.30.0.5:9000");
    expect(manager.list()).toContain("gate123"); // tracked before connect/start, per the brief

    expect(calls.map((args) => args[0])).toEqual(["create", "network", "start", "logs", "inspect"]);
    expect(calls[0]).toEqual(expect.arrayContaining(["attack-net", "-e", "UPSTREAM_HOST=10.0.0.9"]));
    expect(calls[1]).toEqual(["network", "connect", "chain-net", "gate123"]);
    expect(calls[2]).toEqual(["start", "gate123"]);
    expect(calls[4].join(" ")).toContain("attack-net");
  });

  // Fix round 1: a post-create step failing (here `network connect`) must reap
  // the already-tracked container before rethrowing, so a partial launch never
  // escapes the caller's per-run cleanup (which only knows ids the helper
  // returned). Assert both the `docker rm -f` and that tracking is dropped.
  it("reaps its container when a post-create step throws (partial launch)", async () => {
    state.calls = [];
    state.queue = [
      { stdout: "gate123\n" },                       // docker create (tracked)
      { err: new Error("docker network connect failed") }, // connectNetwork throws
      { stdout: "" },                                // docker rm -f (self-clean)
    ];
    const manager = new SandboxManager();

    await expect(
      launchGateContainer(manager, {
        network: { attack: "attack-net", chain: "chain-net" },
        upstreamHost: "10.0.0.9",
      }),
    ).rejects.toThrow(/network connect/);

    expect(state.calls.map((args) => args[0])).toEqual(["create", "network", "rm"]);
    expect(state.calls[2]).toEqual(["rm", "-f", "gate123"]);
    expect(manager.list()).not.toContain("gate123"); // dropped from tracking
  });
});

describe("provisionPhase", () => {
  // Regression: the untrusted attack phase writes into a writable overlay
  // (/workspace) that `--memory` doesn't bound. `--ulimit fsize` caps any
  // single file the phase's untrusted code can create; it belongs on the
  // phase container only (not hardeningFlags(), shared with the trusted
  // confirmer, which may legitimately write larger build/localnet output).
  it("creates the phase container with a --ulimit fsize cap", async () => {
    const calls = stubDocker([
      "phase123\n", // docker create
      "",           // cp context.json
      "",           // cp attack script
      "",           // cp runner.ts
      "",           // cp chain-discovery.ts
      "",           // cp target-src dir
      "",           // docker start
    ]);
    const manager = new SandboxManager();

    const { id } = await provisionPhase(manager, {
      network: "attack-net",
      gateUrl: "http://172.30.0.5:9000",
      context: { packageId: "0xabc" },
      targetDir: materializeMount(
        sanitize([{ path: "sources/example.move", contents: "module challenge::example {}" }]),
      ),
      runnerBundle: { runner: "/host/runner.ts", chainDiscovery: "/host/chain-discovery.ts" },
      attackScript: { name: "attack.ts", contents: "export function attack() {}" },
    });

    expect(id).toBe("phase123");
    expect(calls[0][0]).toBe("create");
    expect(calls[0]).toEqual(
      expect.arrayContaining(["--ulimit", `fsize=${256 * 1024 * 1024}`]),
    );
    // fsize is the phase-only cap layered on top of hardeningFlags()'s shared
    // nofile ulimit — both --ulimit pairs must be present, not one replacing
    // the other.
    expect(calls[0]).toEqual(
      expect.arrayContaining(["--ulimit", `nofile=${CONTAINER_LIMITS.nofile}`]),
    );
  });
});
