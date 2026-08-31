import type Anthropic from "@anthropic-ai/sdk";
import type {
  EffortLevel,
  ModelClient,
  ModelRequest,
  ModelResponse,
  Msg,
  ToolDef,
  ContentPart,
  StopReason,
} from "./types.js";
import { resolveModel } from "./registry.js";

export function toAnthropicTools(tools: ToolDef[]): Anthropic.Tool[] {
  return tools.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: t.inputSchema as Anthropic.Tool["input_schema"],
  }));
}

export function toAnthropicMessages(messages: Msg[]): Anthropic.MessageParam[] {
  return messages.map((m) => {
    if (m.role === "assistant" && m.raw !== undefined) {
      return {
        role: "assistant",
        content: m.raw as Anthropic.MessageParam["content"],
      };
    }
    const blocks = m.content.flatMap((p): Anthropic.ContentBlockParam[] => {
      if (p.type === "text") return [{ type: "text", text: p.text }];
      if (p.type === "tool_call")
        return [
          {
            type: "tool_use",
            id: p.id,
            name: p.name,
            input: p.input as Record<string, unknown>,
          },
        ];
      if (p.type === "tool_result")
        return [
          { type: "tool_result", tool_use_id: p.callId, content: p.content },
        ];
      return []; // thinking without raw is dropped
    });
    return { role: m.role, content: blocks };
  });
}

// Moved from agent.ts: rolling cache breakpoint on the most recent message so
// the growing prefix is a cache read each turn.
export function withRollingCacheBreakpoint(
  messages: Anthropic.MessageParam[],
): Anthropic.MessageParam[] {
  if (messages.length === 0) return messages;
  const result = messages.slice();
  const last = result[result.length - 1];
  const cache = { cache_control: { type: "ephemeral" as const } };
  if (typeof last.content === "string") {
    result[result.length - 1] = {
      ...last,
      content: [{ type: "text", text: last.content, ...cache }],
    };
    return result;
  }
  const blocks = last.content.slice();
  if (blocks.length === 0) return messages;
  blocks[blocks.length - 1] = { ...blocks[blocks.length - 1], ...cache };
  result[result.length - 1] = { ...last, content: blocks };
  return result;
}

export function fromAnthropicMessage(msg: Anthropic.Message): ModelResponse {
  const content: ContentPart[] = [];
  for (const b of msg.content) {
    if (b.type === "text") content.push({ type: "text", text: b.text });
    else if (b.type === "thinking")
      content.push({
        type: "thinking",
        text: (b as { thinking: string }).thinking,
      });
    else if (b.type === "tool_use")
      content.push({
        type: "tool_call",
        id: b.id,
        name: b.name,
        input: b.input,
      });
  }
  const stopReason: StopReason =
    msg.stop_reason === "tool_use"
      ? "tool_use"
      : msg.stop_reason === "max_tokens"
        ? "max_tokens"
        : msg.stop_reason === "refusal"
          ? "refusal"
          : "end_turn";
  return {
    content,
    stopReason,
    raw: msg.content,
    usage: {
      inputTokens: msg.usage.input_tokens,
      outputTokens: msg.usage.output_tokens,
      cacheReadTokens: msg.usage.cache_read_input_tokens ?? 0,
      cacheWriteTokens: msg.usage.cache_creation_input_tokens ?? 0,
    },
    ...(msg.stop_reason === "refusal"
      ? {
          refusal: {
            category: msg.stop_details?.category ?? null,
            explanation: msg.stop_details?.explanation ?? null,
          },
        }
      : {}),
  };
}

/** Extended-thinking token budget for one `effort` tier, mirroring the Google
 *  adapter's effort→budget ladder. Clamped to `[1024, maxTokens-1024]` because
 *  `budget_tokens` must be ≥1024 and leave room for the response under the shared
 *  `max_tokens` ceiling. */
export function effortToBudgetTokens(
  effort: EffortLevel,
  maxTokens: number,
): number {
  const ladder: Record<EffortLevel, number> = {
    low: 1024,
    medium: 4096,
    high: 8192,
    xhigh: 16384,
    max: 32768,
  };
  return Math.min(ladder[effort], Math.max(1024, maxTokens - 1024));
}

export interface ReasoningParams {
  thinking?:
    | { type: "adaptive"; display: "summarized" }
    | { type: "enabled"; budget_tokens: number };
  output_config?: { effort: "low" | "medium" | "high" | "xhigh" | "max" };
}

/** Render the one semantic `effort` knob into the wire params THIS model
 *  accepts, per its ReasoningMode. `adaptive` → adaptive thinking + effort;
 *  `extended` → manual thinking with an effort-mapped budget; anything else
 *  (`effort`/`none`, i.e. non-Anthropic models that never reach this adapter)
 *  → nothing. */
export function anthropicReasoningParams(
  model: string,
  effort: EffortLevel,
  maxTokens: number,
): ReasoningParams {
  switch (resolveModel(model).reasoning) {
    case "adaptive":
      return {
        thinking: { type: "adaptive", display: "summarized" },
        output_config: { effort },
      };
    case "extended":
      return {
        thinking: {
          type: "enabled",
          budget_tokens: effortToBudgetTokens(effort, maxTokens),
        },
      };
    default:
      return {};
  }
}

export class AnthropicModelClient implements ModelClient {
  constructor(private readonly client: Anthropic) {}

  async send(req: ModelRequest): Promise<ModelResponse> {
    const stream = this.client.messages.stream({
      model: req.model,
      max_tokens: req.maxTokens,
      ...anthropicReasoningParams(req.model, req.effort, req.maxTokens),
      system: req.system
        ? [
            {
              type: "text",
              text: req.system,
              cache_control: { type: "ephemeral" },
            },
          ]
        : undefined,
      tools: toAnthropicTools(req.tools),
      messages: withRollingCacheBreakpoint(toAnthropicMessages(req.messages)),
    });
    return fromAnthropicMessage(await stream.finalMessage());
  }
}
