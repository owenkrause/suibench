import Anthropic from "@anthropic-ai/sdk";
import { resolveModel } from "./registry.js";
import { AnthropicModelClient } from "./anthropic.js";
import { OpenAIModelClient } from "./openai.js";
import { GoogleModelClient } from "./google.js";
import type { ModelClient } from "./types.js";

export type {
  ModelClient,
  ModelRequest,
  ModelResponse,
  Msg,
  ContentPart,
  ToolDef,
  Usage,
  Role,
  StopReason,
  RefusalInfo,
  EffortLevel,
  ModelEntry,
  ProviderId,
} from "./types.js";

export {
  clampMaxTokens,
  resolveModel,
  MODEL_REGISTRY,
  REFERENCE_MODEL,
} from "./registry.js";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v)
    throw new Error(`Missing required env var ${name} for the selected model.`);
  return v;
}

export function getModelClient(model: string): ModelClient {
  const entry = resolveModel(model);
  switch (entry.provider) {
    case "anthropic":
      return new AnthropicModelClient(
        new Anthropic({ apiKey: requireEnv(entry.apiKeyEnv) }),
      );
    case "openai":
      return new OpenAIModelClient({
        apiKey: requireEnv(entry.apiKeyEnv),
        baseURL: entry.baseUrlEnv
          ? process.env[entry.baseUrlEnv] || undefined
          : undefined,
        supportsReasoning: entry.validEfforts.length > 0,
      });
    case "google":
      return new GoogleModelClient({
        apiKey: requireEnv(entry.apiKeyEnv),
        supportsReasoning: entry.validEfforts.length > 0,
      });
  }
}
