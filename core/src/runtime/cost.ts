// CostMeter — folds `usage` at the SEND seam. Every model call flows through
// `meter(usage)`, which accumulates token counts cache-weighted: cached reads
// count at ~10% of input cost, cache creation at full input cost, so
// `inputTokens` approximates billable cost rather than raw prefix size.
//
// TURNS are NOT metered here. A turn is an auditor-specific notion (one
// model↔tool round-trip); the send seam has no concept of it. The `AuditorPolicy`
// meters turns explicitly (`meter.tick()`), keeping the send-seam meter reusable
// by any consumer that isn't turn-structured.
import type {
  ModelClient,
  ModelRequest,
  ModelResponse,
  Usage,
} from "./models/index.js";

export interface CostTotals {
  inputTokens: number;
  outputTokens: number;
  turns: number;
}

export class CostMeter {
  private inputTokens = 0;
  private outputTokens = 0;
  private turns = 0;

  /** Fold one response's usage into the running totals (the send seam). */
  meter(usage: Usage): void {
    this.inputTokens +=
      usage.inputTokens +
      usage.cacheWriteTokens +
      Math.ceil(usage.cacheReadTokens * 0.1);
    this.outputTokens += usage.outputTokens;
  }

  /** Count one auditor turn. Metered by the policy, not the send seam. */
  tick(): void {
    this.turns++;
  }

  totals(): CostTotals {
    return {
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      turns: this.turns,
    };
  }
}

/**
 * Wrap a `ModelClient` so every `send` folds its response usage into `meter`.
 * The send seam is the single place token cost is captured; wrapping keeps the
 * agent loop from having to remember to meter each call.
 */
export function meteredClient(
  client: ModelClient,
  meter: CostMeter,
): ModelClient {
  return {
    async send(req: ModelRequest): Promise<ModelResponse> {
      const res = await client.send(req);
      meter.meter(res.usage);
      return res;
    },
  };
}
