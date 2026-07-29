// AuditorPolicy self-test — the audit loop as a Policy, WITHOUT Docker or a live
// model. A fake in-memory Sandbox stands in for the container; a scripted
// ModelClient feeds a fixed turn sequence. Proves: the loop executes tool calls
// against the sandbox, buffers findings.json rows as report_exploit actions, and
// drives cleanly through the Task-4 `collectReports` pattern.
import { describe, it, expect, vi } from "vitest";
import type {
  Sandbox,
  ExecResult,
  Observation,
  Action,
} from "core";
import { sanitize } from "core";
import { SandboxFileNotFoundError } from "../ports/sandbox.js";
import {
  AuditorPolicy,
  pruneStaleToolResults,
  buildToolset,
  CostMeter,
  type EnabledTools,
} from "./index.js";
import type { ModelClient, ModelResponse, Msg } from "./models/index.js";

// ── A fake sandbox: an in-memory file store driven by the `echo b64|base64 -d`
//    write idiom and `cat`. Enough to exercise write_file + copyOut faithfully.
function fakeSandbox(seed: Record<string, string> = {}): Sandbox & {
  files: Map<string, string>;
} {
  const files = new Map<string, string>(Object.entries(seed));
  return {
    files,
    async exec(cmd: string): Promise<ExecResult> {
      // write_file idiom: echo '<b64>' | base64 -d > <path>
      const m = cmd.match(/^echo '([^']*)' \| base64 -d > (.+)$/);
      if (m) {
        files.set(m[2], Buffer.from(m[1], "base64").toString("utf-8"));
        return { stdout: "", stderr: "", exitCode: 0 };
      }
      const cat = cmd.match(/^cat (.+)$/);
      if (cat) {
        const v = files.get(cat[1]);
        return v !== undefined
          ? { stdout: v, stderr: "", exitCode: 0 }
          : { stdout: "", stderr: "no such file", exitCode: 1 };
      }
      return { stdout: `ran: ${cmd}`, stderr: "", exitCode: 0 };
    },
    async writeFile(path: string, content: string): Promise<void> {
      files.set(path, content);
    },
    async copyOut(path: string): Promise<Buffer> {
      const v = files.get(path);
      if (v === undefined) throw new SandboxFileNotFoundError(path);
      return Buffer.from(v, "utf-8");
    },
    async teardown() {},
  };
}

/** A ModelClient that replays a fixed list of ModelResponses, one per send. */
function scriptedClient(responses: ModelResponse[]): {
  client: ModelClient;
  sends: Msg[][];
} {
  const sends: Msg[][] = [];
  let i = 0;
  return {
    sends,
    client: {
      async send(req): Promise<ModelResponse> {
        sends.push(req.messages);
        return responses[Math.min(i++, responses.length - 1)];
      },
    },
  };
}

function usage() {
  return {
    inputTokens: 10,
    outputTokens: 5,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
  };
}

const OBS: Observation = {
  source: sanitize([{ path: "sources/vault.move", contents: "module c {}" }]),
  tools: { bash: true, writeFile: true, references: true },
  env: { network: "devnet", model: "claude-opus-4-8", effort: "low" },
};

async function collectReports(policy: AuditorPolicy, obs: Observation) {
  const actions: Action[] = [];
  for (let i = 0; i < 32; i++) {
    const a = await policy.act(obs);
    if (a.kind === "report_exploit") {
      actions.push(a);
    } else break;
  }
  return actions;
}

describe("AuditorPolicy — loop + buffering", () => {
  it("runs the tool loop, then buffers a report_exploit per findings.json row", async () => {
    const findings = JSON.stringify([
      {
        id: "vuln-001",
        module: "vault",
        severity: "high",
        title: "Drainable pool",
        description: "withdraw has no auth",
        exploitScript: "exploit-vuln-001.mts",
      },
    ]);
    const sandbox = fakeSandbox();
    // Turn 1: the model writes findings.json + the exploit script, then Turn 2 ends.
    const { client } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [
          {
            type: "tool_call",
            id: "t1",
            name: "write_file",
            input: { path: "findings.json", content: findings },
          },
          {
            type: "tool_call",
            id: "t2",
            name: "write_file",
            input: {
              path: "exploit-vuln-001.mts",
              content: "export async function attack(ctx){}",
            },
          },
        ],
      },
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "done" }],
      },
    ]);

    const policy = new AuditorPolicy({
      sandbox,
      client,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
    });

    const reports = await collectReports(policy, OBS);
    expect(reports).toHaveLength(1);
    const first = reports[0];
    expect(first.kind).toBe("report_exploit");
    if (first.kind === "report_exploit") {
      expect(first.exploit.finding.id).toBe("vuln-001");
      expect(first.exploit.finding.severity).toBe("high");
      expect(first.exploit.script.path).toBe("exploit-vuln-001.mts");
      expect(first.exploit.script.contents).toContain("attack(ctx)");
    }
    expect(policy.stopReason()).toBe("end_turn");
  });

  it("returns a terminal sentinel when no findings.json is written", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "nothing found" }],
      },
    ]);
    const policy = new AuditorPolicy({
      sandbox,
      client,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
    });
    const reports = await collectReports(policy, OBS);
    expect(reports).toHaveLength(0);
    // the driver saw a non-report action first — the sentinel.
    const sentinel = await policy.act(OBS);
    expect(sentinel.kind).toBe("run_bash");
  });

  it("meters turns explicitly and folds token usage at the send seam", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [
          { type: "tool_call", id: "t1", name: "bash", input: { command: "ls" } },
        ],
      },
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "done" }],
      },
    ]);
    const meter = new CostMeter();
    const policy = new AuditorPolicy({
      sandbox,
      client,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
      meter,
    });
    await collectReports(policy, OBS);
    const totals = policy.costs();
    expect(totals.turns).toBe(2); // two model turns
    expect(totals.inputTokens).toBe(20); // 10 + 10, no cache
    expect(totals.outputTokens).toBe(10); // 5 + 5
  });

  it("stops at maxTurns (never reports without findings.json)", async () => {
    const sandbox = fakeSandbox();
    // Always asks for a tool call — would loop forever without the cap.
    const { client } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [
          { type: "tool_call", id: "t", name: "bash", input: { command: "ls" } },
        ],
      },
    ]);
    const policy = new AuditorPolicy({
      sandbox,
      client,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
      maxTurns: 3,
    });
    const reports = await collectReports(policy, OBS);
    expect(reports).toHaveLength(0);
    expect(policy.stopReason()).toBe("max_turns");
    expect(policy.costs().turns).toBe(3);
  });

  it("rejects invalid maxTurns instead of turning the cost bound off", () => {
    const { client } = scriptedClient([]);
    expect(
      () =>
        new AuditorPolicy({
          sandbox: fakeSandbox(),
          client,
          systemPrompt: "sys",
          model: "claude-opus-4-8",
          maxTurns: Number.NaN,
        }),
    ).toThrow(/positive integer/);
  });

  it("surfaces a model API failure instead of scoring it as no findings", async () => {
    const policy = new AuditorPolicy({
      sandbox: fakeSandbox(),
      client: {
        async send() {
          throw new Error("authentication failed");
        },
      },
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
    });

    await expect(policy.act(OBS)).rejects.toMatchObject({
      name: "AgentError",
      attempts: 1,
    });
    expect(policy.stopReason()).toBe("error");
  });

  it("surfaces a model error stop reason instead of scoring it as no findings", async () => {
    const { client } = scriptedClient([{
      content: [{ type: "text", text: "provider failed" }],
      stopReason: "error",
      usage: usage(),
    }]);
    const policy = new AuditorPolicy({
      sandbox: fakeSandbox(),
      client,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
    });

    await expect(policy.act(OBS)).rejects.toMatchObject({
      name: "AgentError",
      attempts: 1,
    });
    expect(policy.stopReason()).toBe("error");
  });

  it("surfaces a sandbox transport failure while collecting output", async () => {
    const sandbox = fakeSandbox();
    sandbox.copyOut = async () => {
      throw new Error("docker daemon unavailable");
    };
    const { client } = scriptedClient([{
      content: [{ type: "text", text: "done" }],
      stopReason: "end_turn",
      usage: usage(),
    }]);
    const policy = new AuditorPolicy({
      sandbox,
      client,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
    });

    await expect(policy.act(OBS)).rejects.toMatchObject({
      name: "AgentError",
      message: expect.stringMatching(/findings\.json/),
    });
  });

  it("executes bash tool calls against the injected sandbox", async () => {
    const sandbox = fakeSandbox();
    const spy = vi.spyOn(sandbox, "exec");
    const { client } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [
          {
            type: "tool_call",
            id: "t",
            name: "bash",
            input: { command: "rg -n withdraw target/" },
          },
        ],
      },
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "done" }],
      },
    ]);
    const policy = new AuditorPolicy({
      sandbox,
      client,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      effort: "low",
    });
    await collectReports(policy, OBS);
    expect(spy).toHaveBeenCalledWith("rg -n withdraw target/");
  });
});

describe("pruneStaleToolResults (ported)", () => {
  const toolMsg = (id: string, content: string): Msg => ({
    role: "user",
    content: [{ type: "tool_result", callId: id, content }],
  });

  it("elides large old tool_result content, keeps recent untouched", () => {
    const big = "x".repeat(5_000);
    const out = pruneStaleToolResults(
      [toolMsg("a", big), toolMsg("b", big), toolMsg("c", "recent")],
      { keepRecentMessages: 1, maxToolResultChars: 1_000 },
    );
    const p0 = out[0].content[0];
    if (p0.type === "tool_result")
      expect(p0.content).toContain("stale tool output elided");
    // recent message keeps referential identity
    expect(out[2].content[0]).toEqual({
      type: "tool_result",
      callId: "c",
      content: "recent",
    });
  });
});

describe("buildToolset (ported)", () => {
  it("respects disabled capabilities (static arm: write_file only)", () => {
    const tools = buildToolset({ bash: false, references: false });
    expect(tools.map((t) => t.name)).toEqual(["write_file"]);
  });
  it("defaults to the full toolset", () => {
    expect(buildToolset().map((t) => t.name)).toEqual([
      "bash",
      "write_file",
      "list_references",
      "read_reference",
    ]);
  });
});

describe("runTool — tool gating + injection safety", () => {
  // A sandbox that records every exec + writeFile so we can prove what ran.
  function spySandbox() {
    const execs: string[] = [];
    const writes: { path: string; content: string }[] = [];
    const sb: Sandbox = {
      async exec(cmd) {
        execs.push(cmd);
        return { stdout: "", stderr: "", exitCode: 0 };
      },
      async writeFile(path, content) {
        writes.push({ path, content });
      },
      async copyOut() {
        throw new SandboxFileNotFoundError("findings.json");
      },
      async teardown() {},
    };
    return { sb, execs, writes };
  }

  // Drive one turn where the model emits `call`, then ends; return the tool_result.
  async function toolResultFor(
    enabled: EnabledTools,
    call: { name: string; input: unknown },
    spy: ReturnType<typeof spySandbox>,
  ): Promise<string> {
    const { client, sends } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [{ type: "tool_call", id: "c1", name: call.name, input: call.input }],
      },
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "done" }],
      },
    ]);
    const policy = new AuditorPolicy({
      sandbox: spy.sb,
      client,
      systemPrompt: "sp",
      model: "claude-opus-4-8",
      effort: "low",
      enabledTools: enabled,
    });
    await policy.act(OBS);
    for (const p of (sends[1] ?? []).flatMap((m) => m.content)) {
      if (p.type === "tool_result") return p.content;
    }
    return "";
  }

  it("rejects a bash call when bash is disabled — never execs", async () => {
    const spy = spySandbox();
    const out = await toolResultFor(
      { bash: false, writeFile: true },
      { name: "bash", input: { command: "touch pwned" } },
      spy,
    );
    expect(out).toMatch(/not available/);
    expect(spy.execs).toEqual([]);
  });

  it("rejects an unknown tool name — never runs it as bash", async () => {
    const spy = spySandbox();
    const out = await toolResultFor(
      { bash: true, writeFile: true },
      { name: "totally_made_up", input: { command: "touch pwned" } },
      spy,
    );
    expect(out).toMatch(/unknown tool/);
    expect(spy.execs).toEqual([]);
  });

  it("write_file cannot inject a command: the path is inert data, no shell", async () => {
    const spy = spySandbox();
    const out = await toolResultFor(
      { bash: false, writeFile: true },
      { name: "write_file", input: { path: "x; touch pwned", content: "hi" } },
      spy,
    );
    expect(spy.execs).toEqual([]); // never shells out
    expect(spy.writes).toEqual([{ path: "x; touch pwned", content: "hi" }]);
    expect(out).toMatch(/Wrote/);
  });
});
