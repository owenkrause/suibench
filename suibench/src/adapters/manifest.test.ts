import { describe, it, expect } from "vitest";
import { captureManifest, perturbationManifest, type ManifestDeps } from "./manifest.js";

function deps(over: Partial<ManifestDeps> = {}): ManifestDeps {
  return {
    async run(cmd, args) {
      if (cmd === "docker" && args[0] === "run") return "sui 1.42.0-abc\n";
      if (cmd === "docker" && args[0] === "image") return "sha256:deadbeef\n";
      if (cmd === "git") return "abc1234\n";
      throw new Error(`unexpected ${cmd} ${args.join(" ")}`);
    },
    readPackageJson: () => JSON.stringify({ dependencies: { "@mysten/sui": "^2.15.0" } }),
    ...over,
  };
}

describe("captureManifest", () => {
  it("populates every field from healthy probes", async () => {
    const m = await captureManifest({ untrusted: "suibench-untrusted-runtime", confirmer: "suibench-confirmer", gate: "suibench-gate" }, deps());
    expect(m.images.untrusted.name).toBe("suibench-untrusted-runtime");
    expect(m.images.confirmer.name).toBe("suibench-confirmer");
    expect(m.images.gate.name).toBe("suibench-gate");
    expect(m.images.untrusted.sui_version).toBe("sui 1.42.0-abc");
    expect(m.images.untrusted.id).toBe("sha256:deadbeef");
    expect(m.mysten_sui_version).toBe("^2.15.0");
    expect(m.git_commit).toBe("abc1234");
    expect(typeof m.node_version).toBe("string");
    expect(m.node_version.length).toBeGreaterThan(0);
  });

  it("nulls a field whose probe throws, without failing the run", async () => {
    const m = await captureManifest({ untrusted: "img", confirmer: "img", gate: "img" }, deps({
      run: async (cmd, args) => {
        if (cmd === "git") throw new Error("not a repo");
        if (cmd === "docker" && args[0] === "run") return "sui 1.42.0\n";
        if (cmd === "docker" && args[0] === "image") return "sha256:x\n";
        throw new Error("unexpected");
      },
    }));
    expect(m.git_commit).toBeNull();
    expect(m.images.untrusted.sui_version).toBe("sui 1.42.0");
  });

  it("nulls mysten_sui_version when package.json is unreadable", async () => {
    const m = await captureManifest({ untrusted: "img", confirmer: "img", gate: "img" }, deps({ readPackageJson: () => null }));
    expect(m.mysten_sui_version).toBeNull();
  });

  it("nulls mysten_sui_version when reading package.json throws", async () => {
    const m = await captureManifest({ untrusted: "img", confirmer: "img", gate: "img" }, deps({
      readPackageJson: () => {
        throw new Error("permission denied");
      },
    }));
    expect(m.mysten_sui_version).toBeNull();
  });

  it("throws when an image is missing (no id) instead of recording null provenance", async () => {
    await expect(
      captureManifest({ untrusted: "gone", confirmer: "img", gate: "img" }, deps({
        run: async (cmd, args) => {
          if (cmd === "docker" && args[0] === "image") throw new Error("No such image: gone");
          if (cmd === "docker" && args[0] === "run") return "sui 1.42.0\n";
          if (cmd === "git") return "abc\n";
          throw new Error(`unexpected ${cmd} ${args.join(" ")}`);
        },
      })),
    ).rejects.toThrow(/not found locally/);
  });
});

describe("perturbationManifest", () => {
  it("carries the content-hash version + seed rule + K", () => {
    const p = perturbationManifest(3);
    expect(p.transform_version).toMatch(/^perturb:[0-9a-f]{12}$/);
    expect(p.seed_rule).toContain("sha256");
    expect(p.twins_per_entry).toBe(3);
  });
});
