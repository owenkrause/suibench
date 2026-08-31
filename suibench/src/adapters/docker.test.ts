// Unit coverage for the low-level Docker CLI plumbing: argv construction only —
// no real `docker` invocation. `execFile` is replaced via its promisify.custom
// hook (what `promisify(execFile)` actually calls under the hood), so docker.ts's
// real code path runs end to end against a fake process.
import { describe, it, expect, beforeEach, vi } from "vitest";

const state = vi.hoisted(() => ({
  calls: [] as string[][],
  queue: [] as Array<{ stdout?: string; err?: unknown; hang?: boolean }>,
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
    if (next?.hang) return new Promise(() => {}); // never resolves — simulates a hung docker call
    if (next?.err) throw next.err;
    return { stdout: next?.stdout ?? "", stderr: "" };
  };
  return { execFile };
});

import {
  hardeningFlags,
  createNetwork,
  removeNetwork,
  createContainer,
  startCreated,
  connectNetwork,
  publishedPort,
  dockerWait,
  containerIp,
  startContainer,
  InfraError,
} from "./docker.js";

function stubDocker(stdouts: string[] = [""]): string[][] {
  state.calls = [];
  state.queue = stdouts.map((stdout) => ({ stdout }));
  return state.calls;
}

beforeEach(() => {
  state.calls = [];
  state.queue = [];
});

describe("hardeningFlags", () => {
  it("is shared by run and create (no duplication, no --user in create)", () => {
    const flags = hardeningFlags();
    expect(flags).toEqual(
      expect.arrayContaining(["--cap-drop=ALL", "--security-opt=no-new-privileges", "--ulimit"]),
    );
    expect(flags).not.toContain("--user");
    expect(flags).not.toContain("-d");
    expect(flags).not.toContain("--network");
  });

  it("caps on-disk log growth on every container (--log-opt max-size/max-file)", () => {
    const flags = hardeningFlags();
    expect(flags).toEqual(
      expect.arrayContaining(["--log-opt", "max-size=10m", "--log-opt", "max-file=3"]),
    );
  });
});

describe("createNetwork", () => {
  it("passes --internal, --ipv6=false, and gw-mode-isolated when requested", async () => {
    const calls = stubDocker();
    await createNetwork("attack-net", { internal: true });
    expect(calls[0]).toEqual([
      "network",
      "create",
      "--internal",
      "--ipv6=false",
      "-o",
      "com.docker.network.bridge.gateway_mode_ipv4=isolated",
      "attack-net",
    ]);
  });

  it("omits --internal and gw-mode-isolated by default", async () => {
    const calls = stubDocker();
    await createNetwork("chain-net");
    expect(calls[0]).toEqual(["network", "create", "chain-net"]);
  });
});

describe("removeNetwork", () => {
  it("removes the network", async () => {
    const calls = stubDocker();
    await removeNetwork("attack-net");
    expect(calls[0]).toEqual(["network", "rm", "attack-net"]);
  });

  it("treats an already-gone network as success", async () => {
    stubDocker();
    state.queue = [{ err: new Error("Error response from daemon: No such network: attack-net") }];
    await expect(removeNetwork("attack-net")).resolves.toBeUndefined();
  });

  it("rejects with InfraError on a real removal failure (e.g. a still-attached container)", async () => {
    stubDocker();
    state.queue = [{ err: new Error("network has active endpoints") }];
    await expect(removeNetwork("attack-net")).rejects.toThrow(InfraError);
  });
});

describe("createContainer", () => {
  it("uses `create` (not run), attaches the network, publishes to loopback, no --user", async () => {
    const calls = stubDocker(["deadbeef"]);
    const id = await createContainer({
      image: "img",
      network: "chain-net",
      publish: [{ containerPort: 9000, host: "127.0.0.1" }],
    });
    expect(id).toBe("deadbeef");
    expect(calls[0][0]).toBe("create");
    expect(calls[0]).not.toContain("--user");
    expect(calls[0]).toContain("chain-net");
    expect(calls[0].join(" ")).toMatch(/-p 127\.0\.0\.1::9000/);
    expect(calls[0].at(-1)).toBe("img");
  });

  it("passes env vars and an entrypoint", async () => {
    const calls = stubDocker(["c1"]);
    await createContainer({
      image: "gate-img",
      network: "attack-net",
      env: { UPSTREAM_HOST: "10.0.0.2" },
      entrypoint: ["/bin/sh", "-c", "run.sh"],
    });
    const args = calls[0];
    expect(args).toEqual(
      expect.arrayContaining(["-e", "UPSTREAM_HOST=10.0.0.2", "--entrypoint", "/bin/sh"]),
    );
    // image precedes the entrypoint's trailing args on the create command line
    expect(args.indexOf("gate-img")).toBeLessThan(args.indexOf("-c"));
  });

  it("passes extraArgs through to the create command line", async () => {
    const calls = stubDocker(["c2"]);
    await createContainer({
      image: "img",
      extraArgs: ["--ulimit", "fsize=268435456"],
    });
    expect(calls[0]).toEqual(
      expect.arrayContaining(["--ulimit", "fsize=268435456"]),
    );
  });
});

describe("startCreated", () => {
  it("shells `docker start <id>`", async () => {
    const calls = stubDocker();
    await startCreated("deadbeef");
    expect(calls[0]).toEqual(["start", "deadbeef"]);
  });
});

describe("connectNetwork", () => {
  it("shells `docker network connect <network> <id>`", async () => {
    const calls = stubDocker();
    await connectNetwork("deadbeef", "chain-net");
    expect(calls[0]).toEqual(["network", "connect", "chain-net", "deadbeef"]);
  });
});

describe("publishedPort", () => {
  it("parses the host port off `docker port`", async () => {
    stubDocker(["0.0.0.0:32768\n"]);
    await expect(publishedPort("deadbeef", 9000)).resolves.toBe(32768);
  });

  it("throws InfraError when no port is published", async () => {
    stubDocker([""]);
    await expect(publishedPort("deadbeef", 9000)).rejects.toThrow(InfraError);
  });

  it("wraps a docker exec failure (daemon down/no such container) as InfraError", async () => {
    stubDocker([]);
    state.queue = [{ err: new Error("Cannot connect to the Docker daemon") }];
    await expect(publishedPort("deadbeef", 9000)).rejects.toThrow(InfraError);
  });
});

describe("dockerWait", () => {
  it("shells `docker wait <id>` and parses the exit code", async () => {
    const calls = stubDocker(["0\n"]);
    await expect(dockerWait("deadbeef")).resolves.toEqual({ exitCode: 0, timedOut: false });
    expect(calls[0]).toEqual(["wait", "deadbeef"]);
  });

  it("times out, force-removes, and reports timedOut without throwing", async () => {
    const calls = stubDocker();
    state.queue = [{ hang: true }, { stdout: "" }];
    const res = await dockerWait("cid", { timeoutMs: 50 });
    expect(res).toEqual({ timedOut: true, exitCode: expect.any(Number) });
    expect(calls[0]).toEqual(["wait", "cid"]);
    expect(calls).toContainEqual(["rm", "-f", "cid"]);
  });
});

describe("containerIp", () => {
  it("shells `docker inspect` and returns the trimmed IP", async () => {
    const calls = stubDocker(["172.20.0.3\n"]);
    await expect(containerIp("deadbeef", "attack-net")).resolves.toBe("172.20.0.3");
    expect(calls[0][0]).toBe("inspect");
    expect(calls[0]).toContain("deadbeef");
    expect(calls[0].join(" ")).toContain("attack-net");
  });

  it("throws InfraError when the container has no IP on that network", async () => {
    stubDocker([""]);
    await expect(containerIp("deadbeef", "attack-net")).rejects.toThrow(InfraError);
  });
});

describe("startContainer (post-refactor)", () => {
  it("still emits the run -d --user 1000:1000 --network none shape", async () => {
    const calls = stubDocker(["deadbeef"]);
    await startContainer({ image: "untrusted-img" });
    const args = calls[0];
    expect(args[0]).toBe("run");
    expect(args).toEqual(
      expect.arrayContaining(["-d", "--user", "1000:1000", "--network", "none", "untrusted-img"]),
    );
    expect(args.indexOf("run")).toBe(0);
    expect(args.indexOf("-d")).toBe(1);
  });
});
