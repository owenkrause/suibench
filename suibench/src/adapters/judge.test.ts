import { describe, it, expect } from "vitest";
import type { ModelClient, ModelResponse } from "core/runtime";
import type { Finding, VulnLabel } from "core";
import { makeJudge, parseJudgeResponse } from "./judge.js";

const labels: VulnLabel[] = [
  { id: "a", module: "vault", title: "AdminCap leak", severity: "critical", root_cause: "mints a cap to any caller" },
  { id: "b", module: "vault", title: "Share truncation", severity: "high", root_cause: "integer division truncates shares" },
];
const finding: Finding = {
  id: "f1", module: "vault", severity: "critical",
  title: "Anyone can get admin", description: "request_admin_status hands out AdminCap",
};

/** A ModelClient that returns a fixed text reply. */
function stubClient(reply: string): ModelClient {
  return {
    async send(): Promise<ModelResponse> {
      return {
        content: [{ type: "text", text: reply }],
        stopReason: "end_turn",
        usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 },
      };
    },
  };
}

describe("parseJudgeResponse", () => {
  it("extracts the first in-range integer", () => {
    expect(parseJudgeResponse("1", 2)).toBe(1);
    expect(parseJudgeResponse("index 0 matches", 2)).toBe(0);
  });
  it("maps -1 / out-of-range / no-integer to null", () => {
    expect(parseJudgeResponse("-1", 2)).toBeNull();
    expect(parseJudgeResponse("5", 2)).toBeNull();
    expect(parseJudgeResponse("none", 2)).toBeNull();
  });
});

describe("makeJudge", () => {
  it("returns the matched label index", async () => {
    const judge = makeJudge(stubClient("0"), "judge-model");
    expect(await judge(finding, labels)).toBe(0);
  });
  it("returns null when the model says no match", async () => {
    const judge = makeJudge(stubClient("-1"), "judge-model");
    expect(await judge(finding, labels)).toBeNull();
  });
  it("returns null with no candidates without calling the model", async () => {
    let called = false;
    const client: ModelClient = {
      async send() { called = true; return stubClient("0").send({} as never); },
    };
    expect(await makeJudge(client, "m")(finding, [])).toBeNull();
    expect(called).toBe(false);
  });
  it("classifies a provider failure as an errored model operation", async () => {
    const judge = makeJudge({
      async send() {
        throw new Error("provider unavailable");
      },
    }, "judge-model");
    await expect(judge(finding, labels)).rejects.toMatchObject({
      name: "AgentError",
      message: expect.stringMatching(/judge request failed/),
    });
  });

  it("classifies a token-limited response as an errored model operation", async () => {
    const judge = makeJudge({
      async send() {
        return {
          content: [{ type: "text" as const, text: "0" }],
          stopReason: "max_tokens" as const,
          usage: {
            inputTokens: 10,
            outputTokens: 1024,
            cacheReadTokens: 0,
            cacheWriteTokens: 0,
          },
        };
      },
    }, "judge-model");

    await expect(judge(finding, labels)).rejects.toMatchObject({
      name: "AgentError",
      message: expect.stringMatching(/token limit/),
    });
  });
});
