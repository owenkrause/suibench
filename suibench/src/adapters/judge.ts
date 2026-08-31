// The detect-tier judge: an LLM matches a reported finding to a groundtruth
// label by root cause, returning the matched label index or null. Pinned to the
// judge model (constant across a model sweep), never the model under test.
import { AgentError, type ModelClient } from "core/runtime";
import type { Finding, VulnLabel, JudgeFn } from "core";

/** First integer in the reply, in [0, candidateCount); -1/out-of-range → null. */
export function parseJudgeResponse(
  text: string,
  candidateCount: number,
): number | null {
  const m = text.match(/-?\d+/);
  if (!m) return null;
  const idx = parseInt(m[0], 10);
  if (idx < 0 || idx >= candidateCount) return null;
  return idx;
}

export function makeJudge(client: ModelClient, model: string): JudgeFn {
  return async (finding: Finding, candidates: VulnLabel[]) => {
    if (candidates.length === 0) return null;
    const list = candidates
      .map((c, i) => `[${i}] ${c.title}\nRoot cause: ${c.root_cause}`)
      .join("\n\n");
    const prompt = `A security hunter reported this finding on a smart contract:

Title: ${finding.title}
Description: ${finding.description}

Here are known, labeled vulnerabilities for this contract:

${list}

Which candidate index describes the SAME underlying flaw (same root cause) as the hunter's finding? Reply with ONLY the integer index. If none of them match, reply -1.`;

    let resp;
    try {
      resp = await client.send({
        model,
        maxTokens: 1024,
        effort: "low",
        system: "",
        tools: [],
        messages: [{ role: "user", content: [{ type: "text", text: prompt }] }],
      });
    } catch (err) {
      if (err instanceof AgentError) throw err;
      throw new AgentError(
        `judge request failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (resp.stopReason === "max_tokens") {
      throw new AgentError("judge response exceeded the maximum token limit");
    }
    const text = resp.content
      .filter((b): b is { type: "text"; text: string } => b.type === "text")
      .map((b) => b.text)
      .join("");
    return parseJudgeResponse(text, candidates.length);
  };
}
