// runAgentLoop — the model↔tool loop as a neutral mechanism: it drives the
// conversation to completion against an injected Sandbox and returns raw
// terminal state. It parses NOTHING — no findings.json, no patch.json — it just
// leaves whatever the model wrote in the sandbox for a consumer to read. That
// parse boundary is what lets every consumer share this loop while doing their
// own, different things with the output.
import type { Sandbox } from "../ports/index.js";
import type {
  ModelClient,
  ModelResponse,
  Msg,
  ContentPart,
  ToolDef,
  EffortLevel,
  RefusalInfo,
} from "./models/index.js";
import { clampMaxTokens } from "./models/index.js";
import { CostMeter, meteredClient, type CostTotals } from "./cost.js";

const MAX_RETRIES = 5;

/** A policy run that could not obtain a model response. Bench drivers treat this
 * as an errored entry, never as a legitimate zero-finding score. */
export class AgentError extends Error {
  constructor(
    message: string,
    readonly attempts = 1,
  ) {
    super(message);
    this.name = "AgentError";
  }
}

/** A safety classifier declined the request (`stop_reason: "refusal"` — a real
 * HTTP 200 response, not an infrastructure failure and not a zero-finding
 * result). Distinct from AgentError so a consumer can route a decline into its
 * errored bucket rather than grading it as a legitimate zero score. Carries
 * `attempts` to match the errored-entry shape the bench drivers build. */
export class RefusalError extends Error {
  constructor(
    message: string,
    readonly attempts = 1,
    readonly category: string | null = null,
  ) {
    super(message);
    this.name = "RefusalError";
  }
}

// Context pruning: the conversation prefix is re-read every turn at the cached
// rate, so a long auditor pays O(turns^2) on cache reads. We elide large
// tool_result outputs older than the recent window; the boundary is positional
// and deterministic so an already-pruned prefix stays byte-identical (cache hit).
// Aggressiveness scales inversely with effort.
const EFFORT_PRESETS: Record<
  EffortLevel,
  {
    effort: EffortLevel;
    maxTokens: number;
    toolOutputLimit: number;
    pruneKeepRecentMessages: number;
    pruneMaxToolResultChars: number;
  }
> = {
  low: {
    effort: "low",
    maxTokens: 16_000,
    toolOutputLimit: 50_000,
    pruneKeepRecentMessages: 6,
    pruneMaxToolResultChars: 1_500,
  },
  medium: {
    effort: "medium",
    maxTokens: 32_000,
    toolOutputLimit: 50_000,
    pruneKeepRecentMessages: 8,
    pruneMaxToolResultChars: 2_000,
  },
  high: {
    effort: "high",
    maxTokens: 64_000,
    toolOutputLimit: 100_000,
    pruneKeepRecentMessages: 12,
    pruneMaxToolResultChars: 3_000,
  },
  xhigh: {
    effort: "xhigh",
    maxTokens: 96_000,
    toolOutputLimit: 100_000,
    pruneKeepRecentMessages: 14,
    pruneMaxToolResultChars: 3_500,
  },
  max: {
    effort: "max",
    maxTokens: 128_000,
    toolOutputLimit: 150_000,
    pruneKeepRecentMessages: 16,
    pruneMaxToolResultChars: 4_000,
  },
};

export function buildBashTool(): ToolDef {
  return {
    name: "bash",
    description:
      "Run a shell command in the container. Use this to read files, run the Sui CLI, execute TypeScript exploit scripts with `npx tsx`.",
    inputSchema: {
      type: "object" as const,
      properties: {
        command: {
          type: "string",
          description: "The bash command to execute",
        },
      },
      required: ["command"],
    },
  };
}

export function buildWriteFileTool(): ToolDef {
  return {
    name: "write_file",
    description:
      "Write content to a file. Use this instead of bash heredocs/echo for writing JSON, TypeScript, or any multi-line content. Handles escaping correctly.",
    inputSchema: {
      type: "object" as const,
      properties: {
        path: {
          type: "string",
          description:
            "File path relative to the working directory (e.g. 'findings.json', 'exploit.mts')",
        },
        content: {
          type: "string",
          description: "The full file content to write",
        },
      },
      required: ["path", "content"],
    },
  };
}

export function buildReferenceTools(): ToolDef[] {
  return [
    {
      name: "list_references",
      description:
        "List all available security reference files with descriptions and approximate sizes. Use this to find relevant vulnerability patterns, DeFi deep-dives, or methodology guides for the module you are analyzing.",
      inputSchema: {
        type: "object" as const,
        properties: {},
        required: [],
      },
    },
    {
      name: "read_reference",
      description:
        "Read a security reference file by name. Returns the full content of a specific reference (vulnerability patterns, DeFi deep-dives, false positive catalog, agent methodologies, etc.).",
      inputSchema: {
        type: "object" as const,
        properties: {
          name: {
            type: "string",
            description:
              "The reference name (e.g. 'sui-patterns', 'defi-lending', 'false-positive-catalog'). Use list_references to see available names.",
          },
        },
        required: ["name"],
      },
    },
  ];
}

export interface EnabledTools {
  bash?: boolean;
  writeFile?: boolean;
  references?: boolean;
}

/** Assemble the agent toolset; each capability defaults to enabled. */
export function buildToolset(enabled?: EnabledTools): ToolDef[] {
  const e = enabled ?? {};
  return [
    ...(e.bash !== false ? [buildBashTool()] : []),
    ...(e.writeFile !== false ? [buildWriteFileTool()] : []),
    ...(e.references !== false ? buildReferenceTools() : []),
  ];
}

// Replace large tool_result outputs older than the recent window with a stub.
// Only changed messages are cloned; pruning depends only on a message's distance
// from the end, so the same old region prunes identically every turn.
export function pruneStaleToolResults(
  messages: Msg[],
  opts: { keepRecentMessages: number; maxToolResultChars: number },
): Msg[] {
  const cutoff = messages.length - opts.keepRecentMessages;
  if (cutoff <= 0) return messages;
  return messages.map((msg, idx) => {
    if (idx >= cutoff) return msg;
    let changed = false;
    const content = msg.content.map((part): ContentPart => {
      if (
        part.type === "tool_result" &&
        part.content.length > opts.maxToolResultChars
      ) {
        changed = true;
        return {
          type: "tool_result",
          callId: part.callId,
          content: `[stale tool output elided — ${part.content.length} chars; see agent log]`,
        };
      }
      return part;
    });
    return changed ? { ...msg, content } : msg;
  });
}

/**
 * A reference library the auditor can read via `list_references` /
 * `read_reference`. Injected (not baked) so the runtime kernel holds no
 * filesystem/catalog dependency. `list()` returns the catalog listing;
 * `read(name)` returns one reference's contents. Absent ⇒ the tools report an
 * empty library, matching a run with no reference corpus mounted.
 */
export interface ReferenceLibrary {
  list(): string;
  read(name: string): string;
}

/** How the loop terminated. `refusal` is terminal like `end_turn`, but flags
 * that a safety classifier declined — a consumer decides whether that is an
 * errored entry (bench) or a recorded no-result (audit); it is never a
 * legitimate zero-finding score. */
export type StopKind = "end_turn" | "max_turns" | "error" | "refusal";

export interface AgentLoopConfig {
  client: ModelClient;
  sandbox: Sandbox;
  /** Flattened system prompt, assembled by the caller's prompt builder. */
  systemPrompt: string;
  model: string;
  effort?: EffortLevel;
  maxTurns?: number;
  enabledTools?: EnabledTools;
  references?: ReferenceLibrary;
  /** Cost accumulator; created if omitted. Turns are ticked per model turn. */
  meter?: CostMeter;
}

/** The full conversation a run produced, for a later consumer to persist as a trajectory. */
export interface AgentConversation {
  systemPrompt: string;
  messages: Msg[];
}

export interface AgentResult {
  stopReason: StopKind;
  costs: CostTotals;
  conversation: AgentConversation;
  /** Present only when `stopReason === "refusal"`. */
  refusal?: RefusalInfo;
}

/**
 * Run the model↔tool loop to completion against the injected sandbox. Returns
 * raw terminal state — nothing parsed. Handles the turn structure,
 * retry/backoff, pruning, and maxTurns; the consumer reads the sandbox after.
 */
export async function runAgentLoop(config: AgentLoopConfig): Promise<AgentResult> {
  if (
    config.maxTurns !== undefined &&
    (!Number.isSafeInteger(config.maxTurns) || config.maxTurns < 1)
  )
    throw new RangeError(
      `maxTurns must be a positive integer when provided; got ${config.maxTurns}`,
    );
  const {
    sandbox,
    systemPrompt,
    model,
    maxTurns,
    effort = "medium",
    enabledTools,
    references,
  } = config;
  const meter = config.meter ?? new CostMeter();
  // Fold token usage at the send seam; the loop meters turns explicitly.
  const client = meteredClient(config.client, meter);
  const {
    effort: effortLevel,
    maxTokens,
    toolOutputLimit,
    pruneKeepRecentMessages,
    pruneMaxToolResultChars,
  } = EFFORT_PRESETS[effort];
  const tools = buildToolset(enabledTools);

  let messages: Msg[] = [
    {
      role: "user",
      content: [
        {
          type: "text",
          text: "Begin your security analysis. Find vulnerabilities and confirm them by running your exploit.",
        },
      ],
    },
  ];

  let turns = 0;

  while (!maxTurns || turns < maxTurns) {
    turns++;
    meter.tick();

    let response: ModelResponse | undefined;
    const maxRetries = MAX_RETRIES;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        response = await client.send({
          model,
          maxTokens: clampMaxTokens(model, maxTokens),
          effort: effortLevel,
          system: systemPrompt,
          tools,
          messages: pruneStaleToolResults(messages, {
            keepRecentMessages: pruneKeepRecentMessages,
            maxToolResultChars: pruneMaxToolResultChars,
          }),
        });
        break;
      } catch (err) {
        const isRateLimit =
          String(err).includes("429") || String(err).includes("rate_limit");
        const isOverloaded =
          String(err).includes("529") || String(err).includes("overloaded");
        if ((isRateLimit || isOverloaded) && attempt < maxRetries) {
          const delay = Math.min(2 ** attempt * 5, 60);
          await new Promise((r) => setTimeout(r, delay * 1000));
          continue;
        }
        throw new AgentError(
          `model request failed: ${err instanceof Error ? err.message : String(err)}`,
          attempt + 1,
        );
      }
    }
    if (!response) {
      throw new AgentError("model request failed without a response", maxRetries + 1);
    }

    // Add assistant response to conversation (carry `raw` for lossless replay).
    messages.push({
      role: "assistant",
      content: response.content,
      raw: response.raw,
    });

    if (response.stopReason === "error") {
      throw new AgentError("model response ended with an error stop reason");
    }
    if (response.stopReason === "max_tokens") {
      throw new AgentError("model response exceeded the maximum token limit");
    }
    // A safety-classifier decline is terminal. Reported (not thrown) so each
    // consumer applies its own policy — the bench isolates it as an errored
    // entry, the audit records it and moves on. Never a zero-finding score.
    if (response.stopReason === "refusal") {
      return {
        stopReason: "refusal",
        refusal: response.refusal,
        costs: meter.totals(),
        conversation: { systemPrompt, messages },
      };
    }
    if (response.stopReason !== "tool_use") {
      return {
        stopReason: "end_turn",
        costs: meter.totals(),
        conversation: { systemPrompt, messages },
      };
    }

    // Execute all tool calls against the injected sandbox.
    const toolCalls = response.content.filter(
      (b): b is Extract<ContentPart, { type: "tool_call" }> =>
        b.type === "tool_call",
    );

    const toolResults: ContentPart[] = await Promise.all(
      toolCalls.map(async (block): Promise<ContentPart> => {
        const output = await runTool(block, toolOutputLimit, {
          sandbox,
          enabledTools,
          references,
        });
        return {
          type: "tool_result",
          callId: block.id,
          content: output || "(no output)",
        };
      }),
    );

    // Warn on the second-to-last turn to flush output before the cap.
    if (maxTurns && turns === maxTurns - 1) {
      messages.push({
        role: "user",
        content: [
          ...toolResults,
          {
            type: "text",
            text: `WARNING: You are about to hit your turn limit. This is your LAST turn. Write your output file NOW with whatever analysis you have so far. Note that you hit the turn limit.`,
          },
        ],
      });
    } else {
      messages.push({ role: "user", content: toolResults });
    }
  }

  return {
    stopReason: "max_turns",
    costs: meter.totals(),
    conversation: { systemPrompt, messages },
  };
}

/** Execute one tool call against the sandbox / reference library. */
async function runTool(
  block: Extract<ContentPart, { type: "tool_call" }>,
  toolOutputLimit: number,
  ctx: {
    sandbox: Sandbox;
    enabledTools?: EnabledTools;
    references?: ReferenceLibrary;
  },
): Promise<string> {
  // A tool runs only if enabled for this run (enabled unless explicitly false,
  // matching buildToolset); an unknown/unadvertised name is rejected, never
  // dispatched — so "static" (no bash) has no execution path.
  const e = ctx.enabledTools ?? {};

  switch (block.name) {
    case "list_references":
      if (e.references === false)
        return `(tool "list_references" is not available in this run)`;
      return ctx.references?.list() ?? "(no reference library available)";

    case "read_reference": {
      if (e.references === false)
        return `(tool "read_reference" is not available in this run)`;
      const { name } = block.input as { name: string };
      return (
        ctx.references?.read(name) ??
        `(no reference library available; cannot read "${name}")`
      );
    }

    case "write_file": {
      if (e.writeFile === false)
        return `(tool "write_file" is not available in this run)`;
      const { path, content } = block.input as { path: string; content: string };
      try {
        await ctx.sandbox.writeFile(path, content);
        return `Wrote ${content.length} bytes to ${path}`;
      } catch (err) {
        return `Failed to write ${path}: ${err instanceof Error ? err.message : String(err)}`;
      }
    }

    case "bash": {
      if (e.bash === false) return `(tool "bash" is not available in this run)`;
      const { command } = block.input as { command: string };
      const result = await ctx.sandbox.exec(command);
      return [result.stdout, result.stderr]
        .filter(Boolean)
        .join("\n")
        .slice(0, toolOutputLimit);
    }

    default:
      return `(unknown tool "${block.name}")`;
  }
}
