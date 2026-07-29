import { describe, it, expect } from "vitest";
import type { Observation, MoveFile } from "core";
import { AgentError, type CostMeter, type CostTotals } from "core/runtime";
import { benchPatch, type PatchDeps, type PatchPolicy } from "./patch-driver.js";
import { SandboxManager } from "../adapters/sandbox.js";
import { resolve } from "node:path";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function resolveEntry(name: string): string {
  return resolve(import.meta.dirname, "../../dataset", name);
}

describe("benchPatch — cost callback", () => {
  it("rejects a selection with no patch-gradable entries", async () => {
    const root = mkdtempSync(join(tmpdir(), "suibench-patch-"));
    const dir = join(root, "detect-only");
    mkdirSync(dir);
    writeFileSync(join(dir, "entry.json"), JSON.stringify({
      version: 1,
      vulns: [{
        id: "vuln",
        module: "example",
        title: "example",
        severity: "high",
        root_cause: "root cause",
      }],
    }));
    try {
      await expect(
        benchPatch(
          [dir],
          { network: "devnet", model: "m", effort: "low" },
          1,
          "static",
          {
            manager: new SandboxManager(true),
            patchFor: () => ({
              async collectPatch(): Promise<MoveFile[]> {
                throw new Error("must not run");
              },
            }),
          },
        ),
      ).rejects.toThrow(/no patch-gradable entries/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("calls onEntryCost per functional entry with a produced patch", async () => {
    // A patch policy that produces an empty patch set → graded as noPatch (no
    // Docker needed: gradePatch short-circuits when patched.length === 0).
    const seen: string[] = [];
    const manager = new SandboxManager(true);
    const deps: PatchDeps = {
      manager,
      patchFor: (_e, _o: Observation, meter?: CostMeter): PatchPolicy => ({
        async collectPatch(): Promise<MoveFile[]> { meter?.tick(); return []; },
      }),
      concurrency: 2,
      onEntryCost: (target: string, cost: CostTotals) => seen.push(`${target}:${cost.turns}`),
    };
    const env = { network: "devnet", model: "m", effort: "low" } as const;
    const score = await benchPatch([resolveEntry("capability_leak")], env, 1, "static", deps);
    expect(score.scored).toBe(1);
    expect(seen).toEqual(["capability_leak:1"]);
  });

  it("runs entries concurrently while keeping pass@k inside each entry sequential", async () => {
    let inFlight = 0;
    let peak = 0;
    let sameTargetOverlap = false;
    const activeTargets = new Set<string>();
    const calls = new Map<string, number>();
    const manager = new SandboxManager(true);
    const score = await benchPatch(
      [
        resolveEntry("capability_leak"),
        resolveEntry("unchecked_arithmetic"),
      ],
      { network: "devnet", model: "m", effort: "low" },
      2,
      "static",
      {
        manager,
        concurrency: 2,
        patchFor: (entry): PatchPolicy => ({
          async collectPatch(): Promise<MoveFile[]> {
            if (activeTargets.has(entry.target)) sameTargetOverlap = true;
            activeTargets.add(entry.target);
            calls.set(entry.target, (calls.get(entry.target) ?? 0) + 1);
            inFlight++;
            peak = Math.max(peak, inFlight);
            await new Promise((resolve) => setTimeout(resolve, 10));
            inFlight--;
            activeTargets.delete(entry.target);
            return [];
          },
        }),
      },
    );
    expect(score.scored).toBe(2);
    expect(peak).toBe(2);
    expect(sameTargetOverlap).toBe(false);
    expect(Object.fromEntries(calls)).toEqual({
      capability_leak: 2,
      unchecked_arithmetic: 2,
    });
  });

  it("isolates a model API failure as an errored entry", async () => {
    const manager = new SandboxManager(true);
    const costs: Record<string, CostTotals> = {};
    const score = await benchPatch(
      [
        resolveEntry("capability_leak"),
        resolveEntry("unchecked_arithmetic"),
      ],
      { network: "devnet", model: "m", effort: "low" },
      1,
      "static",
      {
        manager,
        concurrency: 2,
        patchFor: (entry, _observation, meter): PatchPolicy => ({
          async collectPatch(): Promise<MoveFile[]> {
            if (entry.target === "capability_leak") {
              meter?.tick();
              throw new AgentError("provider unavailable", 3);
            }
            return [];
          },
        }),
        onEntryCost: (target, cost) => {
          costs[target] = cost;
        },
      },
    );
    expect(score.scored).toBe(1);
    expect(score.erroredEntries[0]).toMatchObject({
      target: "capability_leak",
      attempts: 3,
    });
    expect(costs.capability_leak).toMatchObject({ turns: 1 });
  });
});
