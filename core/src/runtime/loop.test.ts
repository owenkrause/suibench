// runAgentLoop self-test — the model↔tool loop in isolation, WITHOUT any
// consumer's findings.json parse layered on top. Proves: the loop drives the
// scripted model to completion, runs tool calls against the injected sandbox,
// leaves model output in the sandbox untouched, and reports the right
// stopReason/costs, using a fakeSandbox/scriptedClient pattern.
import { describe, it, expect } from "vitest";
import type { Sandbox, ExecResult } from "../ports/index.js";
import { SandboxFileNotFoundError } from "../ports/index.js";
import { AgentError, runAgentLoop } from "./loop.js";
import type { ModelClient, ModelResponse, Msg } from "./models/index.js";

function fakeSandbox(seed: Record<string, string> = {}): Sandbox & {
  files: Map<string, string>;
} {
  const files = new Map<string, string>(Object.entries(seed));
  return {
    files,
    async exec(cmd: string): Promise<ExecResult> {
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

describe("runAgentLoop", () => {
  it("runs the loop and leaves output in the sandbox, parsing nothing", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [
          {
            type: "tool_call",
            id: "t1",
            name: "write_file",
            input: { path: "findings.json", content: "[]" },
          },
        ],
      },
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "done" }],
      },
    ]);

    const res = await runAgentLoop({
      client,
      sandbox,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      enabledTools: { writeFile: true },
    });

    expect(res.stopReason).toBe("end_turn");
    expect(res.costs.turns).toBe(2);
    expect((await sandbox.copyOut("findings.json")).toString()).toBe("[]");
  });

  it("returns the full conversation — systemPrompt plus the tool_call/tool_result turn in order", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [
          {
            type: "tool_call",
            id: "t1",
            name: "write_file",
            input: { path: "findings.json", content: "[]" },
          },
        ],
      },
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "done" }],
      },
    ]);

    const res = await runAgentLoop({
      client,
      sandbox,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      enabledTools: { writeFile: true },
    });

    expect(res.conversation.systemPrompt).toBe("sys");
    const roles = res.conversation.messages.map((m) => m.role);
    expect(roles).toEqual(["user", "assistant", "user", "assistant"]);

    const toolCallMsg = res.conversation.messages[1];
    expect(toolCallMsg.role).toBe("assistant");
    expect(toolCallMsg.content).toEqual([
      {
        type: "tool_call",
        id: "t1",
        name: "write_file",
        input: { path: "findings.json", content: "[]" },
      },
    ]);

    const toolResultMsg = res.conversation.messages[2];
    expect(toolResultMsg.role).toBe("user");
    expect(toolResultMsg.content).toEqual([
      {
        type: "tool_result",
        callId: "t1",
        content: "Wrote 2 bytes to findings.json",
      },
    ]);
  });

  it("stops at maxTurns without ever parsing findings.json", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "tool_use",
        usage: usage(),
        content: [
          { type: "tool_call", id: "t", name: "bash", input: { command: "ls" } },
        ],
      },
    ]);

    const res = await runAgentLoop({
      client,
      sandbox,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
      maxTurns: 1,
    });

    expect(res.stopReason).toBe("max_turns");
    expect(res.costs.turns).toBe(1);
  });

  it("rejects a response truncated at the provider token limit", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "max_tokens",
        usage: usage(),
        content: [{ type: "text", text: "incomplete analysis" }],
      },
    ]);

    await expect(
      runAgentLoop({
        client,
        sandbox,
        systemPrompt: "sys",
        model: "claude-opus-4-8",
      }),
    ).rejects.toThrow(AgentError);
  });

  it("reports a safety refusal as a distinct terminal stop, not a zero-finding end_turn", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "refusal",
        usage: usage(),
        content: [{ type: "text", text: "I can't help with that." }],
        refusal: { category: "cyber", explanation: "declined" },
      },
    ]);

    const res = await runAgentLoop({
      client,
      sandbox,
      systemPrompt: "sys",
      model: "claude-opus-4-8",
    });

    expect(res.stopReason).toBe("refusal");
    expect(res.refusal).toEqual({ category: "cyber", explanation: "declined" });
    // The decline is still recorded in the conversation for the trajectory.
    expect(res.conversation.messages.at(-1)?.role).toBe("assistant");
  });

  it("rejects a non-positive maxTurns instead of looping unbounded or exiting immediately", async () => {
    const sandbox = fakeSandbox();
    const { client } = scriptedClient([
      {
        stopReason: "end_turn",
        usage: usage(),
        content: [{ type: "text", text: "done" }],
      },
    ]);

    await expect(
      runAgentLoop({
        client,
        sandbox,
        systemPrompt: "sys",
        model: "claude-opus-4-8",
        maxTurns: 0,
      }),
    ).rejects.toThrow(RangeError);

    await expect(
      runAgentLoop({
        client,
        sandbox,
        systemPrompt: "sys",
        model: "claude-opus-4-8",
        maxTurns: -1,
      }),
    ).rejects.toThrow(RangeError);
  });
});
