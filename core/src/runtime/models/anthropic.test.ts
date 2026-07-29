import { describe, it, expect } from "vitest";
import {
  effortToBudgetTokens,
  anthropicReasoningParams,
} from "./anthropic.js";

describe("effortToBudgetTokens", () => {
  it("maps each effort tier to its budget when max_tokens has room", () => {
    expect(effortToBudgetTokens("low", 64_000)).toBe(1024);
    expect(effortToBudgetTokens("medium", 64_000)).toBe(4096);
    expect(effortToBudgetTokens("high", 64_000)).toBe(8192);
    expect(effortToBudgetTokens("xhigh", 64_000)).toBe(16384);
    expect(effortToBudgetTokens("max", 64_000)).toBe(32768);
  });

  it("clamps below max_tokens so thinking leaves room for the response", () => {
    // budget must be < max_tokens; ceiling is maxTokens-1024.
    expect(effortToBudgetTokens("max", 8_000)).toBe(6976); // 8000-1024
    expect(effortToBudgetTokens("medium", 5_000)).toBe(3976); // 5000-1024 < 4096
  });

  it("never drops below the 1024 API minimum", () => {
    expect(effortToBudgetTokens("max", 1_500)).toBe(1024);
    expect(effortToBudgetTokens("low", 500)).toBe(1024);
  });
});

describe("anthropicReasoningParams", () => {
  it("adaptive model: adaptive thinking + effort, no budget", () => {
    const p = anthropicReasoningParams("claude-sonnet-5", "medium", 64_000);
    expect(p.thinking).toEqual({ type: "adaptive", display: "summarized" });
    expect(p.output_config).toEqual({ effort: "medium" });
  });

  it("extended model (Haiku 4.5): manual thinking with an effort-mapped budget, NO effort param", () => {
    const p = anthropicReasoningParams(
      "claude-haiku-4-5-20251001",
      "medium",
      64_000,
    );
    expect(p.thinking).toEqual({ type: "enabled", budget_tokens: 4096 });
    expect(p.output_config).toBeUndefined();
  });

  it("no-reasoning model: sends neither thinking nor effort", () => {
    const p = anthropicReasoningParams("qwen-max", "medium", 32_000);
    expect(p.thinking).toBeUndefined();
    expect(p.output_config).toBeUndefined();
  });
});
