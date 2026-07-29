import OpenAI from "openai";
import type {
  ChatCompletion,
  ChatCompletionMessageParam,
  ChatCompletionTool,
} from "openai/resources/chat/completions";
import type {
  ModelClient,
  ModelRequest,
  ModelResponse,
  Msg,
  ToolDef,
  ContentPart,
  StopReason,
} from "./types.js";

export function toOpenAITools(tools: ToolDef[]): ChatCompletionTool[] {
  return tools.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description,
      parameters: t.inputSchema,
    },
  }));
}

function joinText(parts: ContentPart[]): string {
  return parts
    .filter(
      (p): p is Extract<ContentPart, { type: "text" }> => p.type === "text",
    )
    .map((p) => p.text)
    .join("\n");
}

export function toOpenAIMessages(
  system: string,
  messages: Msg[],
): ChatCompletionMessageParam[] {
  const out: ChatCompletionMessageParam[] = [];
  if (system) out.push({ role: "system", content: system });
  for (const m of messages) {
    const calls = m.content.filter(
      (p): p is Extract<ContentPart, { type: "tool_call" }> =>
        p.type === "tool_call",
    );
    const results = m.content.filter(
      (p): p is Extract<ContentPart, { type: "tool_result" }> =>
        p.type === "tool_result",
    );
    if (m.role === "assistant" && calls.length > 0) {
      out.push({
        role: "assistant",
        content: joinText(m.content) || null,
        tool_calls: calls.map((c) => ({
          id: c.id,
          type: "function",
          function: { name: c.name, arguments: JSON.stringify(c.input ?? {}) },
        })),
      });
    } else if (m.role === "user" && results.length > 0) {
      for (const r of results)
        out.push({ role: "tool", tool_call_id: r.callId, content: r.content });
    } else {
      out.push({
        role: m.role,
        content: joinText(m.content),
      } as ChatCompletionMessageParam);
    }
  }
  return out;
}

export function fromOpenAICompletion(
  completion: ChatCompletion,
): ModelResponse {
  const choice = completion.choices[0];
  const content: ContentPart[] = [];
  if (choice.message.content)
    content.push({ type: "text", text: choice.message.content });
  for (const tc of choice.message.tool_calls ?? []) {
    if (tc.type !== "function") continue;
    let input: unknown = {};
    try {
      input = JSON.parse(tc.function.arguments || "{}");
    } catch {
      input = {};
    }
    content.push({
      type: "tool_call",
      id: tc.id,
      name: tc.function.name,
      input,
    });
  }
  const stopReason: StopReason =
    choice.finish_reason === "tool_calls"
      ? "tool_use"
      : choice.finish_reason === "length"
        ? "max_tokens"
        : "end_turn";
  const u = completion.usage;
  const cacheReadTokens = u?.prompt_tokens_details?.cached_tokens ?? 0;
  return {
    content,
    stopReason,
    usage: {
      // OpenAI prompt_tokens includes cached tokens; the shared meter adds the
      // discounted cache portion separately.
      inputTokens: Math.max(0, (u?.prompt_tokens ?? 0) - cacheReadTokens),
      outputTokens: u?.completion_tokens ?? 0,
      cacheReadTokens,
      cacheWriteTokens: 0,
    },
  };
}

export class OpenAIModelClient implements ModelClient {
  private readonly client: OpenAI;
  constructor(
    private readonly opts: {
      apiKey: string;
      baseURL?: string;
      supportsReasoning: boolean;
    },
  ) {
    this.client = new OpenAI({
      apiKey: opts.apiKey,
      baseURL: opts.baseURL,
      timeout: 600_000,
    });
  }
  async send(req: ModelRequest): Promise<ModelResponse> {
    const completion = await this.client.chat.completions.create({
      model: req.model,
      max_completion_tokens: req.maxTokens,
      messages: toOpenAIMessages(req.system, req.messages),
      tools: req.tools.length > 0 ? toOpenAITools(req.tools) : undefined,
      // effort is CLI-validated against this model's validEfforts (one of
      // low|medium|high for OpenAI), so it passes straight through. The cast
      // satisfies the SDK's narrower enum; no silent downgrade happens here.
      ...(this.opts.supportsReasoning
        ? { reasoning_effort: req.effort as "low" | "medium" | "high" }
        : {}),
    });
    return fromOpenAICompletion(completion);
  }
}
