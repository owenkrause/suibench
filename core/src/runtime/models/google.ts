import { GoogleGenAI } from "@google/genai";
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

type GPart = Record<string, unknown>;
type GContent = { role: "user" | "model"; parts: GPart[] };
type GTool = {
  functionDeclarations: Array<{
    name: string;
    description: string;
    parameters: unknown;
  }>;
};

export function effortToThinkingBudget(effort: EffortLevel): number {
  switch (effort) {
    case "low":
      return 1024;
    case "medium":
      return 4096;
    case "high":
      return 8192;
    case "xhigh":
      return 16384;
    case "max":
      return -1;
  }
}

export function toGoogleTools(tools: ToolDef[]): GTool[] {
  if (tools.length === 0) return [];
  return [
    {
      functionDeclarations: tools.map((t) => ({
        name: t.name,
        description: t.description,
        parameters: t.inputSchema,
      })),
    },
  ];
}

export function toGoogleContents(messages: Msg[]): GContent[] {
  const nameById = new Map<string, string>();
  return messages.map((m) => {
    const parts: GPart[] = [];
    for (const p of m.content) {
      if (p.type === "text") parts.push({ text: p.text });
      else if (p.type === "tool_call") {
        nameById.set(p.id, p.name);
        parts.push({ functionCall: { name: p.name, args: p.input ?? {} } });
      } else if (p.type === "tool_result")
        parts.push({
          functionResponse: {
            name: nameById.get(p.callId) ?? p.callId,
            response: { result: p.content },
          },
        });
      // thinking parts dropped
    }
    return { role: m.role === "assistant" ? "model" : "user", parts };
  });
}

export function fromGoogleResponse(resp: any): ModelResponse {
  const parts: GPart[] = resp.candidates?.[0]?.content?.parts ?? [];
  const content: ContentPart[] = [];
  let hasCall = false;
  let i = 0;
  for (const p of parts) {
    if (typeof (p as any).text === "string")
      content.push({ type: "text", text: (p as any).text });
    else if ((p as any).functionCall) {
      hasCall = true;
      const fc = (p as any).functionCall;
      content.push({
        type: "tool_call",
        id: `call_${i++}`,
        name: fc.name,
        input: fc.args ?? {},
      });
    }
  }
  const stopReason: StopReason =
    resp.candidates?.[0]?.finishReason === "MAX_TOKENS"
      ? "max_tokens"
      : hasCall
        ? "tool_use"
        : "end_turn";
  const u = resp.usageMetadata ?? {};
  const cacheReadTokens = u.cachedContentTokenCount ?? 0;
  return {
    content,
    stopReason,
    usage: {
      inputTokens: Math.max(0, (u.promptTokenCount ?? 0) - cacheReadTokens),
      outputTokens: u.candidatesTokenCount ?? 0,
      cacheReadTokens,
      cacheWriteTokens: 0,
    },
  };
}

export class GoogleModelClient implements ModelClient {
  private readonly ai: GoogleGenAI;
  constructor(
    private readonly opts: { apiKey: string; supportsReasoning: boolean },
  ) {
    this.ai = new GoogleGenAI({ apiKey: opts.apiKey });
  }
  async send(req: ModelRequest): Promise<ModelResponse> {
    const resp = await this.ai.models.generateContent({
      model: req.model,
      contents: toGoogleContents(req.messages) as never,
      config: {
        maxOutputTokens: req.maxTokens,
        systemInstruction: req.system || undefined,
        tools:
          req.tools.length > 0
            ? (toGoogleTools(req.tools) as never)
            : undefined,
        ...(this.opts.supportsReasoning
          ? {
              thinkingConfig: {
                thinkingBudget: effortToThinkingBudget(req.effort),
              },
            }
          : {}),
      },
    });
    return fromGoogleResponse(resp);
  }
}
