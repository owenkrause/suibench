import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { loadEntry } from "../dataset/index.js";
import { SandboxManager } from "../adapters/sandbox.js";
import { gradeSubmission } from "./submission.js";

function resolveEntry(name: string): string {
  return resolve(import.meta.dirname, "../../dataset", name);
}

// A real (but never-invoked) manager: with zero submitted findings the
// exploitation strategy never calls `Confirmer.runOnMount`, so no Docker
// call is made — this test needs no live sandbox.
const fakeManager = new SandboxManager();

describe("gradeSubmission", () => {
  it("runs the exploitation path through runEntryOnce and returns a RunScore", async () => {
    const entry = loadEntry(resolveEntry("capability_leak")); // confirmed-tier
    const score = await gradeSubmission(entry, [], fakeManager);
    expect(score).toBeDefined();
    expect(score.metrics.tier).toBe("confirmed");
    // No submitted exploits => nothing attributed, but the run completes.
    expect(score.metrics.labels_hit).toBe(0);
  });

  it("rejects a detect-tier entry", async () => {
    const entry = loadEntry(resolveEntry("insecure_randomness")); // detect-tier
    await expect(gradeSubmission(entry, [], fakeManager)).rejects.toThrow(
      /confirmed-tier/,
    );
  });
});
