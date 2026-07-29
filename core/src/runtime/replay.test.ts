// ScriptedPolicy / ReplayPolicy — deterministic Policy adapters. These drive the
// same Policy seam as AuditorPolicy but from a fixed script / recorded
// trajectory, so Task 5 has a no-Docker, no-API determinism substrate.
import { describe, it, expect } from "vitest";
import type { Action, Exploit, Observation } from "core";
import type { Trajectory } from "core";
import { sanitize } from "core";
import { ScriptedPolicy, ReplayPolicy } from "./replay.js";

const OBS: Observation = {
  source: sanitize([{ path: "sources/t.move", contents: "module t {}" }]),
  tools: { bash: true, writeFile: true, references: true },
  env: { network: "devnet", model: "m", effort: "low" },
};

function exploit(id: string): Exploit {
  return {
    finding: {
      id,
      module: "vault",
      severity: "high",
      title: id,
      description: "",
    },
    script: { path: `exploit-${id}.mts`, contents: "// attack" },
  };
}

async function drain(policy: {
  act(o: Observation): Promise<Action>;
}): Promise<Action[]> {
  const out: Action[] = [];
  for (let i = 0; i < 16; i++) {
    const a = await policy.act(OBS);
    if (a.kind === "report_exploit") out.push(a);
    else break;
  }
  return out;
}

describe("ScriptedPolicy", () => {
  it("emits its action list, then a terminal sentinel", async () => {
    const actions: Action[] = [
      { kind: "report_exploit", exploit: exploit("a") },
      { kind: "report_exploit", exploit: exploit("b") },
    ];
    const p = new ScriptedPolicy(actions);
    const drained = await drain(p);
    expect(drained.map((a) => (a as any).exploit.finding.id)).toEqual([
      "a",
      "b",
    ]);
    // subsequent calls yield the sentinel forever
    expect((await p.act()).kind).toBe("run_bash");
  });
});

describe("ReplayPolicy", () => {
  it("replays a recorded trajectory's actions in order", async () => {
    const trajectory: Trajectory = {
      id: "run-1",
      target: "capability_leak",
      steps: [
        { observation: OBS, action: { kind: "report_exploit", exploit: exploit("x") } },
        { observation: OBS, action: { kind: "read_reference", name: "sui-patterns" } },
        { observation: OBS, action: { kind: "report_exploit", exploit: exploit("y") } },
      ],
    };
    const p = new ReplayPolicy(trajectory);
    // pull directly (not via drain) so the mixed non-report step is preserved.
    const kinds = [
      (await p.act()).kind,
      (await p.act()).kind,
      (await p.act()).kind,
    ];
    expect(kinds).toEqual([
      "report_exploit",
      "read_reference",
      "report_exploit",
    ]);
  });
});
