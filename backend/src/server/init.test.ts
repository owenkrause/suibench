import { beforeEach, describe, expect, it, vi } from "vitest";

const initGrading = vi.fn();
vi.mock("./grading-runner.js", () => ({
  initGrading: (...args: unknown[]) => initGrading(...args),
}));

describe("ensureReady", () => {
  beforeEach(() => {
    vi.resetModules();
    initGrading.mockReset();
  });

  it("clears the memo on rejection so the next call retries initGrading", async () => {
    initGrading.mockRejectedValueOnce(new Error("transient db hiccup"));
    initGrading.mockResolvedValueOnce(undefined);

    const { ensureReady } = await import("./init.js");

    await expect(ensureReady()).rejects.toThrow("transient db hiccup");
    expect(initGrading).toHaveBeenCalledTimes(1);

    await expect(ensureReady()).resolves.toBeUndefined();
    expect(initGrading).toHaveBeenCalledTimes(2);
  });
});
