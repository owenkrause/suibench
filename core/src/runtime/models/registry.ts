import type { ModelEntry } from "./types.js";

export const REFERENCE_MODEL = "claude-opus-4-8";

/** Single typed source of truth for per-model facts. Numeric fields are
 * maintained by hand. Add a row to support a model. */
export const MODEL_REGISTRY: Record<string, ModelEntry> = {
  // --- Claude 5 generation: adaptive thinking + effort (no extended thinking). ---
  "claude-opus-5": {
    provider: "anthropic",
    maxOutput: 128_000,
    contextWindow: 1_000_000,
    validEfforts: ["low", "medium", "high", "xhigh", "max"],
    reasoning: "adaptive",
    supportsCaching: true,
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  "claude-sonnet-5": {
    provider: "anthropic",
    maxOutput: 128_000,
    contextWindow: 1_000_000,
    validEfforts: ["low", "medium", "high", "xhigh", "max"],
    reasoning: "adaptive",
    supportsCaching: true,
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  "claude-fable-5": {
    provider: "anthropic",
    maxOutput: 128_000,
    contextWindow: 1_000_000,
    validEfforts: ["low", "medium", "high", "xhigh", "max"],
    reasoning: "adaptive",
    supportsCaching: true,
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  // Haiku 4.5 rejects adaptive thinking AND the effort param; it takes only
  // manual extended thinking. The client maps `effort` → `budget_tokens`, so we
  // still expose all effort tiers as the depth knob.
  "claude-haiku-4-5-20251001": {
    provider: "anthropic",
    maxOutput: 64_000,
    contextWindow: 200_000,
    validEfforts: ["low", "medium", "high", "xhigh", "max"],
    reasoning: "extended",
    supportsCaching: true,
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  "claude-opus-4-8": {
    provider: "anthropic",
    maxOutput: 128_000,
    contextWindow: 1_000_000,
    validEfforts: ["low", "medium", "high", "xhigh", "max"],
    reasoning: "adaptive",
    supportsCaching: true,
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  "claude-opus-4-7": {
    provider: "anthropic",
    maxOutput: 128_000,
    contextWindow: 1_000_000,
    validEfforts: ["low", "medium", "high", "xhigh", "max"],
    reasoning: "adaptive",
    supportsCaching: true,
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  // Sonnet 4.6 supports max but NOT xhigh (xhigh is Opus 4.7+ only).
  "claude-sonnet-4-6": {
    provider: "anthropic",
    maxOutput: 64_000,
    contextWindow: 1_000_000,
    validEfforts: ["low", "medium", "high", "max"],
    reasoning: "adaptive",
    supportsCaching: true,
    apiKeyEnv: "ANTHROPIC_API_KEY",
  },
  // OpenAI reasoning_effort tops out at "high".
  "gpt-5": {
    provider: "openai",
    maxOutput: 128_000,
    contextWindow: 400_000,
    validEfforts: ["low", "medium", "high"],
    reasoning: "effort",
    supportsCaching: true,
    apiKeyEnv: "OPENAI_API_KEY",
  },
  o3: {
    provider: "openai",
    maxOutput: 100_000,
    contextWindow: 200_000,
    validEfforts: ["low", "medium", "high"],
    reasoning: "effort",
    supportsCaching: true,
    apiKeyEnv: "OPENAI_API_KEY",
  },
  // Gemini maps each tier to a thinkingBudget, so all tiers are offered.
  "gemini-2.5-pro": {
    provider: "google",
    maxOutput: 65_536,
    contextWindow: 1_048_576,
    validEfforts: ["low", "medium", "high", "xhigh", "max"],
    reasoning: "effort",
    supportsCaching: true,
    apiKeyEnv: "GEMINI_API_KEY",
  },
  // Qwen / local via an OpenAI-compatible endpoint (DashScope/Together/Ollama/vLLM).
  // No reasoning knob → empty validEfforts (effort ignored).
  "qwen-max": {
    provider: "openai",
    maxOutput: 32_000,
    contextWindow: 256_000,
    validEfforts: [],
    reasoning: "none",
    supportsCaching: false,
    apiKeyEnv: "QWEN_API_KEY",
    baseUrlEnv: "QWEN_BASE_URL",
  },
  local: {
    provider: "openai",
    maxOutput: 32_000,
    contextWindow: 128_000,
    validEfforts: [],
    reasoning: "none",
    supportsCaching: false,
    apiKeyEnv: "LOCAL_API_KEY",
    baseUrlEnv: "LOCAL_BASE_URL",
  },
};

export function resolveModel(model: string): ModelEntry {
  const entry = MODEL_REGISTRY[model];
  if (!entry) {
    throw new Error(
      `Unknown model "${model}". Known: ${Object.keys(MODEL_REGISTRY).join(", ")}`,
    );
  }
  return entry;
}

export function clampMaxTokens(model: string, requested: number): number {
  return Math.min(requested, resolveModel(model).maxOutput);
}
