// SandboxManager bookkeeping — the Docker-free lifecycle logic (subsumes the legacy
// ResourceTracker). The docker-shelling paths (spawnAudit/teardownAll removal)
// are covered by the real end-to-end; here we assert the tracked-set semantics
// and that keepContainers suppresses teardown, without invoking docker.
import { describe, it, expect } from "vitest";
import { sanitize } from "core";
import {
  classifyDockerError,
  materializeMount,
  SandboxManager,
} from "./sandbox.js";
import { rmSync, statSync } from "node:fs";
import { join } from "node:path";

describe("SandboxManager", () => {
  it("tracks and forgets container ids", () => {
    const manager = new SandboxManager();
    manager.track("a");
    manager.track("b");
    expect(manager.list().sort()).toEqual(["a", "b"]);
    manager.forget("a");
    expect(manager.list()).toEqual(["b"]);
  });

  it("track is idempotent (a set, not a list)", () => {
    const manager = new SandboxManager();
    manager.track("a");
    manager.track("a");
    expect(manager.list()).toEqual(["a"]);
  });

  it("teardownAll is a no-op (no docker call) when keepContainers=true", async () => {
    const manager = new SandboxManager(true);
    manager.track("a");
    manager.track("b");
    await manager.teardownAll(); // must NOT shell docker; ids stay tracked
    expect(manager.list().sort()).toEqual(["a", "b"]);
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

  it("retries a transient container-removal failure during teardown", async () => {
    let attempts = 0;
    const manager = new SandboxManager(false, {
      async startContainer() {
        return "unused";
      },
      async removeContainer() {
        attempts++;
        if (attempts === 1) throw new Error("temporary Docker failure");
      },
    });
    manager.track("retry-container");

    await manager.teardownAll();

    expect(attempts).toBe(2);
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
