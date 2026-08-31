import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => { vi.resetModules(); vi.unstubAllEnvs(); });

describe("image config", () => {
  it("defaults to the role image names", async () => {
    const m = await import("./images.js");
    expect(m.UNTRUSTED_IMAGE).toBe("suibench-untrusted-runtime");
    expect(m.CONFIRMER_IMAGE).toBe("suibench-confirmer");
  });
  it("honors per-role env overrides", async () => {
    vi.stubEnv("SUIBENCH_UNTRUSTED_IMAGE", "u:test");
    vi.stubEnv("SUIBENCH_CONFIRMER_IMAGE", "c:test");
    vi.resetModules();
    const m = await import("./images.js");
    expect(m.UNTRUSTED_IMAGE).toBe("u:test");
    expect(m.CONFIRMER_IMAGE).toBe("c:test");
  });
});
