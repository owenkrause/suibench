import { describe, it, expect } from "vitest";
import type { Observation, MoveFile } from "core";
import {
  AgentError,
  FileTrajectorySink,
  type AgentConversation,
  type CostMeter,
  type CostTotals,
  type StopKind,
  type TrajectorySink,
} from "core/runtime";
import { benchPatch, type PatchDeps } from "./patch-driver.js";
import { SandboxManager } from "../adapters/sandbox.js";
import { resolve } from "node:path";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function resolveEntry(name: string): string {
  return resolve(import.meta.dirname, "../../dataset", name);
}

const fakeConversation: AgentConversation = {
  systemPrompt: "sys",
  messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }],
};
const fakeCost: CostTotals = { inputTokens: 0, outputTokens: 0, turns: 0 };
const fakeStopReason: StopKind = "end_turn";
const noopSink: TrajectorySink = { save: async () => {} };
const env = { model: "m", effort: "low" } as const;

function reportSources(sources: MoveFile[] = []): {
  sources: MoveFile[];
  conversation: AgentConversation;
  stopReason: StopKind;
  cost: CostTotals;
} {
  return { sources, conversation: fakeConversation, stopReason: fakeStopReason, cost: fakeCost };
}

describe("benchPatch — cost callback", () => {
  it("rejects a selection with no patch-gradable entries", async () => {
    const root = mkdtempSync(join(tmpdir(), "suibench-patch-"));
    const dir = join(root, "detect-only");
    mkdirSync(dir);
    writeFileSync(join(dir, "entry.json"), JSON.stringify({
      id: "chal_00000004",
      version: 1,
      vulns: [{
        id: "vuln",
        module: "example",
        title: "example",
        severity: "high",
        harm: "state",
        root_cause: "root cause",
      }],
    }));
    try {
      await expect(
        benchPatch(
          [dir],
          { model: "m", effort: "low" },
          1,
          "static",
          {
            manager: new SandboxManager(true),
            patchFor: async (): Promise<never> => {
              throw new Error("must not run");
            },
            sink: noopSink,
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
      patchFor: async (_e, _o: Observation, meter?: CostMeter) => {
        meter?.tick();
        return reportSources();
      },
      concurrency: 2,
      onEntryCost: (target: string, cost: CostTotals) => seen.push(`${target}:${cost.turns}`),
      sink: noopSink,
    };
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
        resolveEntry("deepbook_critbit_dos"),
      ],
      env,
      2,
      "static",
      {
        manager,
        concurrency: 2,
        patchFor: async (entry) => {
          if (activeTargets.has(entry.target)) sameTargetOverlap = true;
          activeTargets.add(entry.target);
          calls.set(entry.target, (calls.get(entry.target) ?? 0) + 1);
          inFlight++;
          peak = Math.max(peak, inFlight);
          await new Promise((resolve) => setTimeout(resolve, 10));
          inFlight--;
          activeTargets.delete(entry.target);
          return reportSources();
        },
        sink: noopSink,
      },
    );
    expect(score.scored).toBe(2);
    expect(peak).toBe(2);
    expect(sameTargetOverlap).toBe(false);
    expect(Object.fromEntries(calls)).toEqual({
      capability_leak: 2,
      deepbook_critbit_dos: 2,
    });
  });

  it("isolates a model API failure as an errored entry", async () => {
    const manager = new SandboxManager(true);
    const costs: Record<string, CostTotals> = {};
    const score = await benchPatch(
      [
        resolveEntry("capability_leak"),
        resolveEntry("deepbook_critbit_dos"),
      ],
      env,
      1,
      "static",
      {
        manager,
        concurrency: 2,
        patchFor: async (entry, _observation, meter) => {
          if (entry.target === "capability_leak") {
            meter?.tick();
            throw new AgentError("provider unavailable", 3);
          }
          return reportSources();
        },
        onEntryCost: (target, cost) => {
          costs[target] = cost;
        },
        sink: noopSink,
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

describe("benchPatch — trajectory capture", () => {
  it("saves one trajectory JSON per graded attempt, with the conversation and score", async () => {
    const dir = mkdtempSync(join(tmpdir(), "suibench-patch-trajectory-"));
    try {
      const score = await benchPatch(
        [resolveEntry("capability_leak")],
        env,
        1,
        "static",
        {
          manager: new SandboxManager(true),
          patchFor: async () => reportSources(),
          sink: new FileTrajectorySink(dir),
        },
      );
      const saved = JSON.parse(
        readFileSync(join(dir, "capability_leak-0.json"), "utf-8"),
      );
      expect(saved.conversation.messages.length).toBeGreaterThan(0);
      expect(saved.score).toEqual(score.entries[0].run);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not fail benchPatch() when the trajectory sink rejects", async () => {
    const rejecting: TrajectorySink = {
      save: async () => {
        throw new Error("disk full");
      },
    };
    const score = await benchPatch(
      [resolveEntry("capability_leak")],
      env,
      1,
      "static",
      {
        manager: new SandboxManager(true),
        patchFor: async () => reportSources(),
        sink: rejecting,
      },
    );
    expect(score.scored).toBe(1);
  });
});
