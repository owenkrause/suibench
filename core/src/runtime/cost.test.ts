import { describe, expect, it } from "vitest";
import { CostMeter } from "./cost.js";
import { fromGoogleResponse } from "./models/google.js";
import { fromOpenAICompletion } from "./models/openai.js";

describe("cache-weighted cost", () => {
  it("does not count OpenAI cached prompt tokens twice", () => {
    const response = fromOpenAICompletion({
      choices: [{
        finish_reason: "stop",
        message: { content: "done", tool_calls: [] },
      }],
      usage: {
        prompt_tokens: 100,
        completion_tokens: 10,
        total_tokens: 110,
        prompt_tokens_details: {
          cached_tokens: 40,
          audio_tokens: 0,
        },
        completion_tokens_details: {
          accepted_prediction_tokens: 0,
          rejected_prediction_tokens: 0,
          reasoning_tokens: 0,
          audio_tokens: 0,
        },
      },
    } as never);
    const meter = new CostMeter();
    meter.meter(response.usage);

    expect(response.usage.inputTokens).toBe(60);
    expect(response.usage.cacheReadTokens).toBe(40);
    expect(meter.totals()).toEqual({
      inputTokens: 64,
      outputTokens: 10,
      turns: 0,
    });
  });

  it("does not count Google cached prompt tokens twice", () => {
    const response = fromGoogleResponse({
      candidates: [{
        finishReason: "STOP",
        content: { parts: [{ text: "done" }] },
      }],
      usageMetadata: {
        promptTokenCount: 100,
        candidatesTokenCount: 10,
        cachedContentTokenCount: 40,
      },
    });
    const meter = new CostMeter();
    meter.meter(response.usage);

    expect(response.usage.inputTokens).toBe(60);
    expect(meter.totals().inputTokens).toBe(64);
  });
});
