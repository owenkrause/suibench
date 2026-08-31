// The runtime model transport: the internal seam each provider adapter translates
// its own wire format to/from. Carries tool-call / tool-result content blocks,
// per-provider caching/effort handling, and cache-aware usage.

export type EffortLevel = "low" | "medium" | "high" | "xhigh" | "max";

/** How a model exposes reasoning, so each adapter sends the right wire params
 *  for one semantic `effort` knob (the pattern LiteLLM/inspect-ai use):
 *  - "adaptive" — Anthropic `thinking:{type:"adaptive"}` + `output_config.effort`
 *                 (Opus 4.6+, all 5-series).
 *  - "extended" — Anthropic manual `thinking:{type:"enabled", budget_tokens}`,
 *                 budget mapped from effort (Haiku 4.5, Sonnet 4.5, Opus 4.5).
 *  - "effort"   — a provider-native effort/budget knob the adapter maps itself
 *                 (OpenAI `reasoning_effort`, Google `thinkingBudget`).
 *  - "none"     — no reasoning knob; effort is ignored. */
export type ReasoningMode = "adaptive" | "extended" | "effort" | "none";

export type Role = "user" | "assistant";

export type ContentPart =
  | { type: "text"; text: string }
  | { type: "thinking"; text: string }
  | { type: "tool_call"; id: string; name: string; input: unknown }
  | { type: "tool_result"; callId: string; content: string };

export interface Msg {
  role: Role;
  content: ContentPart[];
  /** Opaque provider-native representation for lossless replay (e.g. Anthropic
   * thinking-block signatures). Set and consumed by the same adapter; ignored
   * by others. */
  raw?: unknown;
}

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export type StopReason =
  | "end_turn"
  | "tool_use"
  | "max_tokens"
  | "error"
  | "refusal";

/** Why a safety classifier declined a request (`stop_reason: "refusal"`).
 *  Category is the provider's open-set label (e.g. "cyber"); both fields may be
 *  null when the provider gives none. */
export interface RefusalInfo {
  category: string | null;
  explanation: string | null;
}

export interface Usage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

export interface ModelRequest {
  model: string;
  maxTokens: number;
  effort: EffortLevel;
  system: string;
  tools: ToolDef[];
  messages: Msg[];
}

export interface ModelResponse {
  content: ContentPart[];
  stopReason: StopReason;
  usage: Usage;
  raw?: unknown;
  /** Present only when `stopReason === "refusal"`. */
  refusal?: RefusalInfo;
}

export interface ModelClient {
  send(req: ModelRequest): Promise<ModelResponse>;
}

export type ProviderId = "anthropic" | "openai" | "google";

export interface ModelEntry {
  provider: ProviderId;
  maxOutput: number;
  contextWindow: number;
  /** Reasoning/effort tiers this model accepts, low→high. Empty = no reasoning
   * knob (effort is ignored). The CLI validates `--effort` against this and
   * errors on an unsupported level rather than silently downgrading. */
  validEfforts: EffortLevel[];
  /** Reasoning mechanism — drives how the adapter renders the `effort` knob into
   *  wire params. See {@link ReasoningMode}. */
  reasoning: ReasoningMode;
  supportsCaching: boolean;
  baseUrlEnv?: string;
  apiKeyEnv: string;
}
