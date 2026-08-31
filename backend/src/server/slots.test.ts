import { describe, expect, it } from "vitest";
import { SlotPool } from "./slots.js";

const tick = () => new Promise((res) => setTimeout(res, 10));

describe("SlotPool", () => {
  it("never runs more than N at once", async () => {
    const pool = new SlotPool(2);
    let active = 0;
    let peak = 0;
    const task = () =>
      pool.withSlot(async () => {
        active++;
        peak = Math.max(peak, active);
        await tick();
        active--;
      });
    await Promise.all(Array.from({ length: 10 }, task));
    expect(peak).toBeLessThanOrEqual(2);
  });

  it("releases the permit only after fn settles, even on throw", async () => {
    const pool = new SlotPool(1);
    await expect(
      pool.withSlot(async () => {
        throw new Error("x");
      }),
    ).rejects.toThrow("x");
    let ran = false;
    await pool.withSlot(async () => {
      ran = true;
    }); // must not deadlock
    expect(ran).toBe(true);
  });

  it("rejects a non-positive capacity", () => {
    expect(() => new SlotPool(0)).toThrow(/must be >= 1/);
  });
});
