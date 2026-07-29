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
  auditorPolicyFactory,
  patchPolicyFactory,
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

function harness(): {
  manager: AuditSandboxManager;
  sandbox: Sandbox & { containerId: string };
  teardownCount: () => number;
} {
  let teardowns = 0;
  const files = new Map<string, string>();
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
  env: { network: "none", model: "claude-opus-4-8", effort: "low" },
};

describe("policy factory lifecycle", () => {
  it("does not disguise an unexpected setup defect as a model error", async () => {
    const defect = new TypeError("broken manager implementation");
    const policy = auditorPolicyFactory({
      manager: {
        async spawnAudit() {
          throw defect;
        },
      },
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    })(entry("capability_leak"), observation);

    await expect(policy.act(observation)).rejects.toBe(defect);
  });

  it("tears down an auditor sandbox after the first act buffers the reports", async () => {
    const h = harness();
    const policy = auditorPolicyFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    })(entry("capability_leak"), observation);

    await policy.act(observation);
    expect(h.teardownCount()).toBe(1);
    await policy.act(observation);
    expect(h.teardownCount()).toBe(1);
  });

  it("tears down an auditor sandbox after a model failure", async () => {
    const h = harness();
    const policy = auditorPolicyFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: {
        async send() {
          throw new Error("authentication failed");
        },
      },
    })(entry("capability_leak"), observation);

    await expect(policy.act(observation)).rejects.toMatchObject({
      name: "AgentError",
    });
    expect(h.teardownCount()).toBe(1);
  });

  it("tears down a patch sandbox after collecting output", async () => {
    const h = harness();
    const policy = patchPolicyFactory({
      manager: h.manager,
      model: "claude-opus-4-8",
      effort: "low",
      client: client(),
    })(entry("capability_leak"), observation);

    expect(await policy.collectPatch()).toEqual([]);
    expect(h.teardownCount()).toBe(1);
  });
});
