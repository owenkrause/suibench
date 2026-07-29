// AuditorPolicy — the real audit agent loop, wearing the `Policy` port.
//
// It is STATEFUL. The FIRST `act()` runs the entire model↔tool conversation to
// completion against its own injected `Sandbox` and BUFFERS the reported
// exploits/findings; each subsequent `act()` returns the next buffered report,
// then a terminal sentinel once drained. So a driver sees only the stream of
// reports, never the tool turns.
//
// Turns are metered EXPLICITLY here (meter.tick() per turn), not at the send
// seam — a turn is auditor-specific. Token usage is folded at the send seam by
// `meteredClient` (cost.ts).
import {
  SandboxFileNotFoundError,
  type Policy,
  type Sandbox,
} from "../ports/index.js";
import type {
  Observation,
  Action,
  Exploit,
  Finding,
  MoveFile,
  Severity,
} from "../kernel/types.js";
import type {
  ModelClient,
  ModelResponse,
  Msg,
  ContentPart,
  ToolDef,
  EffortLevel,
} from "./models/index.js";
import { clampMaxTokens } from "./models/index.js";
import { CostMeter, meteredClient } from "./cost.js";

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

export interface AuditorPolicyOptions {
  sandbox: Sandbox;
  client: ModelClient;
  /** Flattened system prompt (from buildAuditorPrompt). */
  systemPrompt: string;
  model: string;
  effort?: EffortLevel;
  maxTurns?: number;
  enabledTools?: EnabledTools;
  references?: ReferenceLibrary;
  /** Cost accumulator; created if omitted. Turns are ticked per model turn. */
  meter?: CostMeter;
}

/** How the loop terminated — mirrors the legacy AgentResult.stopped. */
export type StopKind = "end_turn" | "max_turns" | "error";

/** A parsed row of the model's findings.json (eval-mode shape). */
interface RawFinding {
  id?: unknown;
  module?: unknown;
  severity?: unknown;
  title?: unknown;
  description?: unknown;
  exploitScript?: unknown;
}

/**
 * The real audit agent as a `Policy`. The first `act()` drives the whole
 * model↔tool conversation over the injected Sandbox to completion, reads the
 * model-authored `findings.json` (+ each `exploit-<id>.mts`) out of the sandbox,
 * and buffers a `report_exploit` action per finding. Subsequent `act()` calls
 * drain the buffer; when empty they return a terminal sentinel so the driver's
 * `collectReports` loop halts.
 */
export class AuditorPolicy implements Policy {
  private readonly sandbox: Sandbox;
  private readonly client: ModelClient;
  private readonly meter: CostMeter;
  private readonly opts: AuditorPolicyOptions;

  private ran = false;
  private queue: Action[] = [];
  private stopped: StopKind = "end_turn";

  constructor(opts: AuditorPolicyOptions) {
    if (
      opts.maxTurns !== undefined &&
      (!Number.isSafeInteger(opts.maxTurns) || opts.maxTurns < 1)
    ) {
      throw new RangeError(
        `maxTurns must be a positive integer when provided; got ${opts.maxTurns}`,
      );
    }
    this.opts = opts;
    this.sandbox = opts.sandbox;
    this.meter = opts.meter ?? new CostMeter();
    // Fold token usage at the send seam; the loop meters turns explicitly.
    this.client = meteredClient(opts.client, this.meter);
  }

  /** The cost totals (input/output tokens + turns) accumulated so far. */
  costs() {
    return this.meter.totals();
  }

  /** How the internal loop terminated (available after the first `act`). */
  stopReason(): StopKind {
    return this.stopped;
  }

  async act(observation: Observation): Promise<Action> {
    if (!this.ran) {
      this.ran = true;
      this.queue = await this.runToCompletion(observation);
    }
    if (this.queue.length > 0) return this.queue.shift()!;
    // Terminal sentinel — any non-report action halts the driver's collect loop.
    return { kind: "run_bash", command: ":" };
  }

  /**
   * Run the model↔tool loop to completion, then collect reports. Ported from
   * runAgent: same turn structure, retry/backoff, pruning, and maxTurns handling.
   */
  private async runToCompletion(_observation: Observation): Promise<Action[]> {
    const {
      systemPrompt,
      model,
      maxTurns,
      effort = "medium",
      enabledTools,
    } = this.opts;
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
      this.meter.tick();

      let response: ModelResponse | undefined;
      const maxRetries = MAX_RETRIES;
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
          response = await this.client.send({
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
          this.stopped = "error";
          throw new AgentError(
            `model request failed: ${err instanceof Error ? err.message : String(err)}`,
            attempt + 1,
          );
        }
      }
      if (!response) {
        this.stopped = "error";
        throw new AgentError("model request failed without a response", maxRetries + 1);
      }

      // Add assistant response to conversation (carry `raw` for lossless replay).
      messages.push({
        role: "assistant",
        content: response.content,
        raw: response.raw,
      });

      if (response.stopReason === "error") {
        this.stopped = "error";
        throw new AgentError("model response ended with an error stop reason");
      }
      if (response.stopReason !== "tool_use") {
        this.stopped = "end_turn";
        return this.collectReports();
      }

      // Execute all tool calls against the injected sandbox.
      const toolCalls = response.content.filter(
        (b): b is Extract<ContentPart, { type: "tool_call" }> =>
          b.type === "tool_call",
      );

      const toolResults: ContentPart[] = await Promise.all(
        toolCalls.map(async (block): Promise<ContentPart> => {
          const output = await this.runTool(block, toolOutputLimit);
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

    this.stopped = "max_turns";
    return this.collectReports();
  }

  /** Execute one tool call against the sandbox / reference library. */
  private async runTool(
    block: Extract<ContentPart, { type: "tool_call" }>,
    toolOutputLimit: number,
  ): Promise<string> {
    // A tool runs only if enabled for this run (enabled unless explicitly false,
    // matching buildToolset); an unknown/unadvertised name is rejected, never
    // dispatched — so "static" (no bash) has no execution path.
    const e = this.opts.enabledTools ?? {};

    switch (block.name) {
      case "list_references":
        if (e.references === false)
          return `(tool "list_references" is not available in this run)`;
        return this.opts.references?.list() ?? "(no reference library available)";

      case "read_reference": {
        if (e.references === false)
          return `(tool "read_reference" is not available in this run)`;
        const { name } = block.input as { name: string };
        return (
          this.opts.references?.read(name) ??
          `(no reference library available; cannot read "${name}")`
        );
      }

      case "write_file": {
        if (e.writeFile === false)
          return `(tool "write_file" is not available in this run)`;
        const { path, content } = block.input as { path: string; content: string };
        try {
          await this.sandbox.writeFile(path, content);
          return `Wrote ${content.length} bytes to ${path}`;
        } catch (err) {
          return `Failed to write ${path}: ${err instanceof Error ? err.message : String(err)}`;
        }
      }

      case "bash": {
        if (e.bash === false) return `(tool "bash" is not available in this run)`;
        const { command } = block.input as { command: string };
        const result = await this.sandbox.exec(command);
        return [result.stdout, result.stderr]
          .filter(Boolean)
          .join("\n")
          .slice(0, toolOutputLimit);
      }

      default:
        return `(unknown tool "${block.name}")`;
    }
  }

  /**
   * After the loop ends, read the model-authored `findings.json` from the
   * sandbox and turn each row into a `report_exploit`. A finding's runnable
   * `exploit-<id>.mts` is copied out to become the `Exploit.script` the confirmer
   * re-runs; a finding with no readable script still reports (script contents
   * empty) so detect-tier findings survive. The policy NEVER fabricates a
   * ChainSnapshot — proof is the Grader's job.
   */
  private async collectReports(): Promise<Action[]> {
    const raw = await this.readSandboxFile("findings.json");
    if (!raw) return [];
    let rows: RawFinding[];
    try {
      const parsed = JSON.parse(raw);
      rows = Array.isArray(parsed) ? (parsed as RawFinding[]) : [];
    } catch {
      return [];
    }

    const actions: Action[] = [];
    for (const row of rows) {
      const finding = toFinding(row);
      if (!finding) continue;
      const script = await this.readExploitScript(row);
      const exploit: Exploit = { finding, script };
      actions.push({ kind: "report_exploit", exploit });
    }
    return actions;
  }

  /**
   * Patch mode: run the loop, then read the model's `patch.json`
   * (`{ patchedSources: [...] }`) and each rewritten source file out of the
   * sandbox. Returns the corrected sources (basename paths) for the driver to
   * overlay; empty if the model produced no patch.
   */
  async collectPatch(observation: Observation): Promise<MoveFile[]> {
    if (!this.ran) {
      this.ran = true;
      this.queue = await this.runToCompletion(observation);
    }
    const manifest = await this.readSandboxFile("patch.json");
    if (!manifest) return [];
    let names: string[];
    try {
      const parsed = JSON.parse(manifest) as { patchedSources?: unknown };
      names = Array.isArray(parsed.patchedSources)
        ? parsed.patchedSources.filter((n): n is string => typeof n === "string")
        : [];
    } catch {
      return [];
    }
    const files: MoveFile[] = [];
    for (const name of names) {
      const base = basename(name);
      const contents = await this.readSandboxFile(`target/sources/${base}`);
      if (contents !== null) files.push({ path: base, contents });
    }
    return files;
  }

  /** Read a text file out of the sandbox, or null when it is genuinely absent. */
  private async readSandboxFile(path: string): Promise<string | null> {
    try {
      const buf = await this.sandbox.copyOut(path);
      return buf.toString("utf-8");
    } catch (err) {
      if (err instanceof SandboxFileNotFoundError) return null;
      this.stopped = "error";
      throw new AgentError(
        `sandbox read failed for ${path}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  /** The runnable exploit artifact for a finding — a `MoveFile` the confirmer re-runs. */
  private async readExploitScript(row: RawFinding): Promise<MoveFile> {
    const name =
      typeof row.exploitScript === "string" && row.exploitScript.length > 0
        ? basename(row.exploitScript)
        : `exploit-${String(row.id ?? "unknown")}.mts`;
    const contents = (await this.readSandboxFile(name)) ?? "";
    return { path: name, contents };
  }
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

/** Coerce one findings.json row into a kernel `Finding`, or null if unusable. */
function toFinding(row: RawFinding): Finding | null {
  const id = typeof row.id === "string" ? row.id : undefined;
  if (!id) return null;
  const severity = SEVERITIES.includes(row.severity as Severity)
    ? (row.severity as Severity)
    : "medium";
  return {
    id,
    module: typeof row.module === "string" ? row.module : "",
    severity,
    title: typeof row.title === "string" ? row.title : "",
    description: typeof row.description === "string" ? row.description : "",
  };
}

/** Last path segment — keeps a model-supplied filename from escaping the dir. */
function basename(p: string): string {
  const seg = p.split("/").pop();
  return seg && seg.length > 0 ? seg : p;
}
