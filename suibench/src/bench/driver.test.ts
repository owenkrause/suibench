import { describe, it, expect } from "vitest";
import type { Policy, Observation, Action } from "core";
import { AgentError, type CostMeter, type CostTotals } from "core/runtime";
import { bench, type BenchDeps, type RunConfig } from "./driver.js";

// A scripted comprehension run needs no Docker: judge is a pure fn, policy
// reports one finding matching the entry's single label.
const config: RunConfig = {
  harness: "static", axis: "comprehension",
  env: { network: "none", model: "m", effort: "low" }, k: 1,
};

function reportOne(): Policy {
  let done = false;
  return {
    async act(): Promise<Action> {
      if (done) return { kind: "run_bash", command: ":" };
      done = true;
      return {
        kind: "report_exploit",
        exploit: {
          finding: { id: "admincap-leak", module: "vault", severity: "critical", title: "t", description: "d" },
          script: { path: "x.mts", contents: "" },
        },
      };
    },
  };
}

describe("bench — cost + concurrency", () => {
  it("invokes onEntryCost once per scored entry and runs concurrently", async () => {
    const seen: string[] = [];
    let inFlight = 0;
    let peak = 0;
    const deps: BenchDeps = {
      policyFor: (_e, _o, meter?: CostMeter) => {
        meter?.tick();
        const policy = reportOne();
        return {
          async act(observation) {
            inFlight++;
            peak = Math.max(peak, inFlight);
            await new Promise((resolve) => setTimeout(resolve, 10));
            inFlight--;
            return policy.act(observation);
          },
        };
      },
      judge: async () => 0, // 0-based label index (single-vuln entry)
      concurrency: 2,
      onEntryCost: (target: string, cost: CostTotals) => seen.push(`${target}:${cost.turns}`),
    };
    const dirs = [
      resolveEntry("capability_leak"),
      resolveEntry("unchecked_arithmetic"),
    ];
    const score = await bench(dirs, config, deps);
    expect(score.scored).toBe(2);
    expect(peak).toBe(2);
    expect(seen.sort()).toEqual([
      "capability_leak:1",
      "unchecked_arithmetic:1",
    ]);
  });

  it("keeps write_file as the static arm's non-executing output channel", async () => {
    let tools: Observation["tools"] | undefined;
    await bench([resolveEntry("capability_leak")], config, {
      policyFor: (_entry, observation) => {
        tools = observation.tools;
        return { act: async () => ({ kind: "run_bash", command: ":" }) };
      },
      judge: async () => null,
    });
    expect(tools).toEqual({ bash: false, writeFile: true, references: false });
  });

  it("rejects static + exploitation before running a policy", async () => {
    await expect(
      bench(
        [resolveEntry("capability_leak")],
        { ...config, axis: "exploitation" },
        { policyFor: () => reportOne() },
      ),
    ).rejects.toThrow(/static \+ exploitation is invalid/);
  });

  it("skips a detect-tier entry on the exploitation axis instead of aborting", async () => {
    // Exploitation grades via the check.ts oracle; a detect-tier entry has none,
    // so it isn't gradeable on this axis. It must be excluded (not throw+abort),
    // and its grader must never be built.
    const score = await bench(
      [resolveEntry("insecure_randomness")],
      { harness: "harnessed", axis: "exploitation", env: { network: "none", model: "m", effort: "low" }, k: 1 },
      {
        policyFor: () => reportOne(),
        graderFor: () => {
          throw new Error("grader must not be built for a skipped entry");
        },
      },
    );
    expect(score.scored).toBe(0);
    expect(score.errored).toBe(0);
    expect(score.entries).toHaveLength(0);
  });

  it("isolates a model API failure as an errored entry", async () => {
    const costs: Record<string, CostTotals> = {};
    const score = await bench(
      [resolveEntry("capability_leak"), resolveEntry("unchecked_arithmetic")],
      config,
      {
        policyFor: (entry, _observation, meter) => {
          if (entry.target === "capability_leak") {
            meter?.tick();
            return {
                async act() {
                  throw new AgentError("provider unavailable", 2);
                },
              };
          }
          return { act: async () => ({ kind: "run_bash", command: ":" }) };
        },
        judge: async () => null,
        concurrency: 2,
        onEntryCost: (target, cost) => {
          costs[target] = cost;
        },
      },
    );
    expect(score.scored).toBe(1);
    expect(score.errored).toBe(1);
    expect(score.erroredEntries[0]).toMatchObject({
      target: "capability_leak",
      attempts: 2,
    });
    expect(costs.capability_leak).toMatchObject({ turns: 1 });
  });
});

import { resolve } from "node:path";
function resolveEntry(name: string): string {
  return resolve(import.meta.dirname, "../../dataset", name);
}
