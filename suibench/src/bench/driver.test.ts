import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type {
  Exploit,
  Finding,
  Observation,
  Check,
  GroundTruth,
  ChainSnapshot,
  Grader,
  MoveFile,
} from "core";
import {
  sanitize,
  balanceGained,
  runCounterfactuals,
  attribute,
  scoreConfirmed,
} from "core";
import {
  AgentError,
  FileTrajectorySink,
  type AgentConversation,
  type CostMeter,
  type CostTotals,
  type StopKind,
  type TrajectorySink,
} from "core/runtime";
import { bench, runEntryOnce, type BenchDeps, type RunConfig } from "./driver.js";
import { loadEntry } from "../dataset/index.js";
import {
  counterfactualBoundary,
  type PatchedLabel,
} from "../adapters/counterfactual-boundary.js";

// A scripted comprehension run needs no Docker: judge is a pure fn, the run
// reports one finding matching the entry's single label.
const config: RunConfig = {
  harness: "static", axis: "comprehension",
  env: { model: "m", effort: "low" }, k: 1,
};

// Non-empty by default so any test that doesn't care about the trajectory
// still produces a plausible one — only the dedicated trajectory tests below
// build their own.
const fakeConversation: AgentConversation = {
  systemPrompt: "sys",
  messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }],
};
const fakeCost: CostTotals = { inputTokens: 0, outputTokens: 0, turns: 0 };
const fakeStopReason: StopKind = "end_turn";
const noopSink: TrajectorySink = { save: async () => {} };

function reportOne(): {
  exploits: Exploit[];
  findings: Finding[];
  conversation: AgentConversation;
  stopReason: StopKind;
  cost: CostTotals;
} {
  const exploit: Exploit = {
    finding: { id: "admincap-leak", module: "vault", severity: "critical", title: "t", description: "d" },
    script: { path: "x.mts", contents: "" },
  };
  return {
    exploits: [exploit],
    findings: [exploit.finding],
    conversation: fakeConversation,
    stopReason: fakeStopReason,
    cost: fakeCost,
  };
}

const reportNone = {
  exploits: [],
  findings: [],
  conversation: fakeConversation,
  stopReason: fakeStopReason,
  cost: fakeCost,
};

describe("bench — cost + concurrency", () => {
  it("invokes onEntryCost once per scored entry and runs concurrently", async () => {
    const seen: string[] = [];
    let inFlight = 0;
    let peak = 0;
    const deps: BenchDeps = {
      runFor: async (_o, meter?: CostMeter) => {
        meter?.tick();
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 10));
        inFlight--;
        return reportOne();
      },
      judge: async () => 0, // 0-based label index (single-vuln entry)
      concurrency: 2,
      onEntryCost: (target: string, cost: CostTotals) => seen.push(`${target}:${cost.turns}`),
      sink: noopSink,
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
      runFor: async (observation) => {
        tools = observation.tools;
        return reportNone;
      },
      judge: async () => null,
      sink: noopSink,
    });
    expect(tools).toEqual({ bash: false, writeFile: true, references: false });
  });

  it("accepts static + exploitation instead of rejecting the cell", async () => {
    // Static exploits are written blind but still re-run by the confirmer, so
    // static + exploitation is a valid cell (the raw-model baseline) and must
    // not throw. A detect-tier entry is still skipped for lack of a check.ts
    // oracle, exactly as under harnessed.
    const score = await bench(
      [resolveEntry("insecure_randomness")],
      { harness: "static", axis: "exploitation", env: { model: "m", effort: "low" }, k: 1 },
      {
        runFor: async () => reportOne(),
        graderFor: () => {
          throw new Error("grader must not be built for a skipped entry");
        },
        sink: noopSink,
      },
    );
    expect(score.entries).toHaveLength(0);
    expect(score.errored).toBe(0);
  });

  it("skips a detect-tier entry on the exploitation axis instead of aborting", async () => {
    // Exploitation grades via the check.ts oracle; a detect-tier entry has none,
    // so it isn't gradeable on this axis. It must be excluded (not throw+abort),
    // and its grader must never be built.
    const score = await bench(
      [resolveEntry("insecure_randomness")],
      { harness: "harnessed", axis: "exploitation", env: { model: "m", effort: "low" }, k: 1 },
      {
        runFor: async () => reportOne(),
        graderFor: () => {
          throw new Error("grader must not be built for a skipped entry");
        },
        sink: noopSink,
      },
    );
    expect(score.scored).toBe(0);
    expect(score.errored).toBe(0);
    expect(score.entries).toHaveLength(0);
  });

  it("isolates a model API failure as an errored entry", async () => {
    const costs: Record<string, CostTotals> = {};
    // A decontaminated run can't know which entry it is, so we can't fail one
    // by name. With concurrency 1 the corpus runs in the passed order, so the
    // first invocation is `capability_leak` — fail that one.
    let firstRun = true;
    const score = await bench(
      [resolveEntry("capability_leak"), resolveEntry("unchecked_arithmetic")],
      config,
      {
        runFor: async (_observation, meter) => {
          if (firstRun) {
            firstRun = false;
            meter?.tick();
            throw new AgentError("provider unavailable", 2);
          }
          return reportNone;
        },
        judge: async () => null,
        concurrency: 1,
        onEntryCost: (target, cost) => {
          costs[target] = cost;
        },
        sink: noopSink,
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

describe("bench — trajectory capture", () => {
  it("saves one trajectory JSON per graded attempt, with the conversation and score", async () => {
    const dir = mkdtempSync(join(tmpdir(), "suibench-trajectory-"));
    try {
      const score = await bench([resolveEntry("capability_leak")], config, {
        runFor: async () => reportOne(),
        judge: async () => 0,
        sink: new FileTrajectorySink(dir),
      });
      const saved = JSON.parse(
        readFileSync(join(dir, "capability_leak-0.json"), "utf-8"),
      );
      expect(saved.conversation.messages.length).toBeGreaterThan(0);
      expect(saved.score).toEqual(score.entries[0].run);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not fail bench() when the trajectory sink rejects", async () => {
    const rejecting: TrajectorySink = {
      save: async () => {
        throw new Error("disk full");
      },
    };
    const score = await bench([resolveEntry("capability_leak")], config, {
      runFor: async () => reportOne(),
      judge: async () => 0,
      sink: rejecting,
    });
    expect(score.scored).toBe(1);
  });
});

import { resolve } from "node:path";
function resolveEntry(name: string): string {
  return resolve(import.meta.dirname, "../../dataset", name);
}

describe("gradeExploitation — per-exploit tmp lifecycle", () => {
  const leaked = () =>
    readdirSync(tmpdir()).filter((n) => n.startsWith("suibench-exploit-"));

  it("leaves no tmp dirs behind, even with no bench() call", async () => {
    const before = leaked().length;
    const entry = loadEntry(resolveEntry("capability_leak"));
    const exploit: Exploit = {
      finding: { id: "admincap-leak", module: "vault", severity: "critical", title: "t", description: "d" },
      script: { path: "exploit.mts", contents: "// noop" },
    };
    const emptySnapshot: ChainSnapshot = {
      balances: { byAddress: {} },
      objects: { ownerOf: {}, byId: {} },
    };
    const fakeGrader: Grader = {
      async runOnMount() {
        return {
          delta: { pre: emptySnapshot, post: emptySnapshot },
          params: { packageId: "0x0", attackerAddress: "0xattacker", adminAddress: "0xadmin" },
          evidence: { attackTransactions: [] },
        };
      },
    };
    await runEntryOnce(
      entry,
      { harness: "harnessed", axis: "exploitation", env: { model: "m", effort: "low" }, k: 1 },
      {
        runFor: async () => ({
          exploits: [exploit],
          findings: [exploit.finding],
          conversation: fakeConversation,
          stopReason: fakeStopReason,
          cost: fakeCost,
        }),
        graderFor: () => fakeGrader,
        sink: noopSink,
      },
    );
    expect(leaked().length).toBe(before);
  });
});

// --- exploitation axis: attribution invariants ---------------------------------
// The reward-hacking controls, graded through the SHIPPED scoring: the real
// `counterfactualBoundary` adapter + the kernel's runCounterfactuals / attribute
// / scoreConfirmed, with a fake Grader standing in for the networked Confirmer.
// gradeExploitation (driver.ts) composes exactly these pieces; its disk-loading
// glue is covered by verify:graders on localnet.
const ATTACKER = "0xattacker";
const COIN = "0xpkg::asset::ASSET";
const THRESHOLD = 500n;

// One labeled bug; its patch overlay REPLACES the source with a marked variant
// the fake grader detects (mirroring the real Confirmer, which sees only the
// mount + script). The vulnerable build carries no marker.
const GROUNDTRUTH: GroundTruth = {
  target: "reward_pool",
  vulns: [{
    id: "reward-pool-drain",
    module: "reward_pool",
    title: "Reward pool drain",
    severity: "high",
    root_cause: "missing access control on withdraw",
  }],
};
const LABELS: PatchedLabel[] = [{
  id: "reward-pool-drain",
  patchFiles: [{
    path: "sources/reward_pool.move",
    contents: "module reward_pool { /* patched:reward-pool-drain */ }",
  }],
}];
const VULN_MOUNT = sanitize([
  { path: "sources/reward_pool.move", contents: "module reward_pool {}" },
]);

// Mechanism-anchored check: the attacker gained >= THRESHOLD of the reserve coin
// (post - pre, so a seeded baseline is measured, not ignored). Returns the
// entry's manifest label id as the witness, or [] — a structured CheckResult,
// not a boolean.
const drainCheck: Check = (delta, params) =>
  balanceGained(delta, params.attackerAddress, COIN) >= THRESHOLD
    ? { witnesses: [GROUNDTRUTH.vulns[0].id] }
    : { witnesses: [] };

function balSnap(amount: bigint): ChainSnapshot {
  return {
    balances: { byAddress: { [ATTACKER]: { [COIN]: amount } } },
    objects: { ownerOf: {}, byId: {} },
  };
}

function exploitIdOf(script: MoveFile): string {
  return (script.path.split("/").pop() ?? script.path).replace(/\.mts$/, "");
}

// Fake Grader: a canned ChainDelta per (script, variant). It sees ONLY the mount
// + script (the Grader port) and reads the variant off the overlaid patch marker.
function fakeGrader(preBalance = 0n): Grader {
  const GAIN = 1000n;
  const params = { packageId: "0x0", attackerAddress: ATTACKER };
  return {
    async runOnMount(mount, script) {
      const patched = mount.files.some((f) =>
        f.contents.includes("patched:reward-pool-drain"),
      );
      const id = exploitIdOf(script);
      // gold: gains on base, the patch breaks it. cheat: gains on EVERY variant
      // (patch-invariant). anything else: no gain (fails the check on base).
      const gain = id === "gold-1" ? (patched ? 0n : GAIN) : id === "cheat-1" ? GAIN : 0n;
      return {
        delta: { pre: balSnap(preBalance), post: balSnap(preBalance + gain) },
        params,
        evidence: { attackTransactions: [] },
      };
    },
  };
}

function exploitFor(id: string): Exploit {
  return {
    finding: { id, module: "reward_pool", severity: "high", title: id, description: "synthetic" },
    script: { path: `exploits/${id}.mts`, contents: `// ${id}` },
  };
}

// The runCheck authoring guard's allowed-witness universe for this synthetic
// entry: every manifest vuln id.
const ALLOWED_WITNESS_IDS = GROUNDTRUTH.vulns.map((v) => v.id);

// Compose the real boundary + kernel over the reported exploits -> RunScore.
async function gradeReport(exploits: Exploit[], grader: Grader) {
  const findings = exploits.map((e) => e.finding);
  const scripts = new Map(exploits.map((e) => [e.script.path, e.script]));
  const runs = [];
  for (const e of exploits) {
    // Each exploit gets its own boundary so baseProof doesn't cross-contaminate.
    const { boundary } = counterfactualBoundary({
      grader,
      vulnerableMount: VULN_MOUNT,
      readScript: (p) => scripts.get(p)!,
      check: drainCheck,
      allowedWitnessIds: ALLOWED_WITNESS_IDS,
      label: "reward_pool",
    });
    runs.push(await runCounterfactuals("", e.finding.id, e.script.path, LABELS, boundary));
  }
  return scoreConfirmed(findings, GROUNDTRUTH, attribute(runs));
}

describe("exploitation axis — attribution invariants", () => {
  it("gold ⇒ attributes to the real label (recall + true positive)", async () => {
    const score = await gradeReport([exploitFor("gold-1")], fakeGrader());
    expect(score.metrics.tier).toBe("confirmed");
    expect(score.metrics.labels_hit).toBe(1);
    expect(score.metrics.recall).toBe(1);
    expect(score.metrics.true_positives).toBe(1);
    expect(score.metrics.false_positives).toBe(0);
    expect(score.metrics.unattributed_findings).toBe(0);
    expect(score.metrics.attribution_rate).toBe(1);
    expect(score.labels[0].status).toBe("HIT");
    expect(score.labels[0].id).toBe("reward-pool-drain");
  });

  it("transfer-cheat ⇒ confirmed but unattributed (no label credited)", async () => {
    const score = await gradeReport([exploitFor("cheat-1")], fakeGrader());
    expect(score.findings[0].classification).toBe("UNATTRIBUTED");
    expect(score.findings[0].confirmed).toBe(true);
    expect(score.metrics.false_positives).toBe(0);
    expect(score.metrics.unattributed_findings).toBe(1);
    expect(score.metrics.true_positives).toBe(0);
    expect(score.metrics.labels_hit).toBe(0);
    expect(score.metrics.precision).toBeNull();
    expect(score.metrics.attribution_rate).toBe(0);
    expect(score.metrics.recall).toBe(0);
    expect(score.labels.every((l) => l.status === "MISS")).toBe(true);
  });

  it("claim without grader confirmation ⇒ refuted, counted a false positive", async () => {
    const score = await gradeReport([exploitFor("refuted-1")], fakeGrader());
    expect(score.findings[0].classification).toBe("FP");
    expect(score.metrics.false_positives).toBe(1);
    expect(score.metrics.unattributed_findings).toBe(0);
  });

  it("null ⇒ recall 0, no confirmed labels", async () => {
    const score = await gradeReport([], fakeGrader());
    expect(score.metrics.labels_hit).toBe(0);
    expect(score.metrics.recall).toBe(0);
    expect(score.metrics.true_positives).toBe(0);
    expect(score.metrics.false_positives).toBe(0);
    expect(score.metrics.unattributed_findings).toBe(0);
    expect(score.metrics.attribution_rate).toBeNull();
    expect(score.labels.every((l) => l.status === "MISS")).toBe(true);
  });

  it("seeded pre ⇒ gold still attributes when the baseline is non-empty (post - pre)", async () => {
    // Attacker held 100_000 after setup; the gold delta gains 1000 OVER that.
    // balanceGained (post - pre) still clears THRESHOLD; reading raw post would
    // spuriously pass every variant and break attribution.
    const score = await gradeReport([exploitFor("gold-1")], fakeGrader(100_000n));
    expect(score.metrics.labels_hit).toBe(1);
    expect(score.metrics.recall).toBe(1);
    expect(score.metrics.false_positives).toBe(0);
  });
});
