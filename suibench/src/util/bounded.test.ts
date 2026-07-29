import { describe, it, expect } from "vitest";
import { boundedMap } from "./bounded.js";

describe("boundedMap", () => {
  it("returns results in input order regardless of completion order", async () => {
    const delays = [30, 5, 20, 1];
    const out = await boundedMap(delays, 2, async (d, i) => {
      await new Promise((r) => setTimeout(r, d));
      return i;
    });
    expect(out).toEqual([0, 1, 2, 3]);
  });

  it("never runs more than `limit` at once", async () => {
    let inFlight = 0;
    let peak = 0;
    await boundedMap([...Array(10).keys()], 3, async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
    });
    expect(peak).toBe(3);
  });

  it("propagates the first rejection", async () => {
    await expect(
      boundedMap([1, 2, 3], 2, async (n) => {
        if (n === 2) throw new Error("boom");
        return n;
      }),
    ).rejects.toThrow("boom");
  });

  it("stops scheduling and drains in-flight work before rejecting", async () => {
    const started: number[] = [];
    let active = 0;
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const run = boundedMap([0, 1, 2], 2, async (n) => {
      started.push(n);
      active++;
      try {
        if (n === 0) throw new Error("boom");
        await blocked;
        return n;
      } finally {
        active--;
      }
    });

    const earlyState = await Promise.race([
      run.then(
        () => "resolved",
        () => "rejected",
      ),
      new Promise<"pending">((resolve) =>
        setTimeout(() => resolve("pending"), 10),
      ),
    ]);
    release();
    await expect(run).rejects.toThrow("boom");
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(earlyState).toBe("pending");
    expect(active).toBe(0);
    expect(started).toEqual([0, 1]);
  });

  it("handles an empty list", async () => {
    expect(await boundedMap([], 3, async () => 1)).toEqual([]);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects an invalid limit (%s)",
    async (limit) => {
      await expect(boundedMap([1], limit, async (n) => n)).rejects.toThrow(
        /positive integer/,
      );
    },
  );
});
