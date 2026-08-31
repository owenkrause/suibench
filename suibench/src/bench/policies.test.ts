import { describe, expect, it } from "vitest";
import {
  SandboxFileNotFoundError,
  sanitize,
  type Observation,
  type Sandbox,
} from "core";
import type { ModelClient } from "core/runtime";
import { loadEntry } from "../dataset/index.js";
import {
  auditorRunFactory,
  patchRunFactory,
  type AuditSandboxManager,
} from "./policies.js";
import { resolve } from "node:path";

function entry(name: string) {
  return loadEntry(resolve(import.meta.dirname, "../../dataset", name));
}

function client(): ModelClient {
  return {
    async send() {
      return {
        content: [{ type: "text" as const, text: "done" }],
        stopReason: "end_turn" as const,
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
        },
      };
    },
  };
}

function harness(seed: Record<string, string> = {}): {
  manager: AuditSandboxManager;
  sandbox: Sandbox & { containerId: string };
  teardownCount: () => number;
} {
  let teardowns = 0;
  const files = new Map<string, string>(Object.entries(seed));
  const sandbox = {
    containerId: "fake",
    async exec() {
      return { stdout: "", stderr: "", exitCode: 0 };
    },
    async copyOut(path: string) {
      const value = files.get(path);
      if (value === undefined) throw new SandboxFileNotFoundError(path);
      return Buffer.from(value);
    },
    async writeFile(path: string, contents: string) {
      files.set(path, contents);
    },
    async teardown() {
      teardowns++;
    },
  };
  return {
    sandbox,
    manager: { async spawnAudit() { return sandbox; } },
    teardownCount: () => teardowns,
  };
}

const observation: Observation = {
  source: sanitize([{ path: "sources/vault.move", contents: "module challenge::vault {}" }]),
  tools: { bash: false, writeFile: true, references: false },
  env: { model: "claude-opus-4-8", effort: "low" },
};

describe("run factory lifecycle", () => {
  it("does not disguise an unexpected setup defect as a model error", async () => {
    const defect = new TypeError("broken manager implementation");
    const runFor = auditorRunFactory({
      manager: {
        async spawnAudit() {
          throw defect;
        },
      },
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    });

    await expect(runFor(observation)).rejects.toBe(defect);
  });

  it("tears down an auditor sandbox after the run parses its reports", async () => {
    const h = harness();
    const runFor = auditorRunFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    });

    // No findings.json written ⇒ a zero-finding run, not an error.
    expect(await runFor(observation)).toMatchObject({
      exploits: [],
      findings: [],
    });
    expect(h.teardownCount()).toBe(1);
  });

  it("returns what the loop left in the sandbox, parsed", async () => {
    const h = harness({
      "findings.json": JSON.stringify([
        {
          id: "admincap-leak",
          module: "vault",
          severity: "critical",
          title: "AdminCap is public",
          description: "anyone can mint",
          exploitScript: "exploit-admincap-leak.mts",
        },
      ]),
      "exploit-admincap-leak.mts": "// attack",
    });
    const runFor = auditorRunFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    });

    const { exploits, findings, conversation, stopReason, cost } =
      await runFor(observation);
    expect(exploits).toHaveLength(1);
    expect(exploits[0].script).toEqual({
      path: "exploit-admincap-leak.mts",
      contents: "// attack",
    });
    expect(findings).toEqual([exploits[0].finding]);
    // The loop's conversation/stopReason/cost surface unmodified — the
    // trajectory sink (bench/driver.ts) is what persists them.
    expect(conversation.messages.length).toBeGreaterThan(0);
    expect(stopReason).toBe("end_turn");
    expect(cost.turns).toBeGreaterThan(0);
    expect(h.teardownCount()).toBe(1);
  });

  it("tears down an auditor sandbox after a model failure", async () => {
    const h = harness();
    const runFor = auditorRunFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: {
        async send() {
          throw new Error("authentication failed");
        },
      },
    });

    await expect(runFor(observation)).rejects.toMatchObject({
      name: "AgentError",
    });
    expect(h.teardownCount()).toBe(1);
  });

  it("tears down a patch sandbox after collecting output", async () => {
    const h = harness();
    const patchFor = patchRunFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    });

    // No patch.json written ⇒ no patch, not an error.
    expect(await patchFor(entry("capability_leak"), observation)).toMatchObject({
      sources: [],
    });
    expect(h.teardownCount()).toBe(1);
  });

  it("returns the patched sources the loop left in the sandbox", async () => {
    const h = harness({
      "patch.json": JSON.stringify({ patchedSources: ["vault.move"] }),
      "target/sources/vault.move": "module challenge::vault { /* fixed */ }",
    });
    const patchFor = patchRunFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    });

    const { sources, conversation, stopReason, cost } =
      await patchFor(entry("capability_leak"), observation);
    expect(sources).toEqual([
      { path: "vault.move", contents: "module challenge::vault { /* fixed */ }" },
    ]);
    expect(conversation.messages.length).toBeGreaterThan(0);
    expect(stopReason).toBe("end_turn");
    expect(cost.turns).toBeGreaterThan(0);
    expect(h.teardownCount()).toBe(1);
  });

  it("tears down a patch sandbox after a model failure", async () => {
    const h = harness();
    const patchFor = patchRunFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: {
        async send() {
          throw new Error("authentication failed");
        },
      },
    });

    await expect(patchFor(entry("capability_leak"), observation)).rejects.toMatchObject({
      name: "AgentError",
    });
    expect(h.teardownCount()).toBe(1);
  });
});
