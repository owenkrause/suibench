import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { RunScore } from "core";
import { evaluateTwinGate } from "./verify-twins.js";
import { readEntryFiles, writeTwinDir, twinSeed } from "../src/bench/materialize.js";
import { generateTwin } from "../src/perturbation/transform.js";

const perfect = (): RunScore => ({
  labels: [], findings: [],
  metrics: { tier: "confirmed", labels_total: 1, labels_hit: 1, findings_total: 1, true_positives: 1, false_positives: 0, unattributed_findings: 0, recall: 1, precision: 1, attribution_rate: 1, severity_accuracy: 1, severity_correct: 1, severity_total: 1 },
} as RunScore);

describe("evaluateTwinGate", () => {
  it("passes when twin grades identically-perfect to the original", () => {
    expect(evaluateTwinGate(perfect(), perfect()).pass).toBe(true);
  });
  it("fails when the twin misses a label the original hit", () => {
    const twin = perfect(); twin.metrics.labels_hit = 0; twin.metrics.recall = 0;
    const r = evaluateTwinGate(perfect(), twin);
    expect(r.pass).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/label/i);
  });
  it("fails on cardinality drift — twin has a different label/finding count", () => {
    const twin = perfect();
    twin.metrics.labels_total = 2; twin.metrics.labels_hit = 2; twin.metrics.findings_total = 2; twin.metrics.true_positives = 2;
    const r = evaluateTwinGate(perfect(), twin);
    expect(r.pass).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/cardinality/i);
  });
});

// Regression for the tmpdir-resolution bug: a twin materialized OUTSIDE the
// workspace tree can't resolve its check.ts's bare `import "core"` (Node walks
// node_modules UP from the importing file; an OS tmpdir never reaches the
// workspace). verify-twins.ts now dumps twins under `suibench/.suibench/`
// (gitignored, in-tree) instead — this proves that location actually resolves
// "core", without needing Docker or the real grader pipeline.
describe("twin materialization resolves \"core\" from the in-tree scratch dir", () => {
  const SCRATCH_ROOT = resolve(import.meta.dirname, "../.suibench");
  let out: string | undefined;

  afterEach(() => {
    if (out) rmSync(out, { recursive: true, force: true });
    out = undefined;
  });

  it("dynamically imports a twin's check.ts without a module-resolution error", async () => {
    const entryDir = resolve(import.meta.dirname, "../dataset/capability_leak");
    const files = readEntryFiles(entryDir);
    const twin = await generateTwin(files, twinSeed("capability_leak", 0));

    mkdirSync(SCRATCH_ROOT, { recursive: true });
    out = mkdtempSync(join(SCRATCH_ROOT, "twin-capability_leak-resolve-test-"));
    writeTwinDir(out, twin);

    // capability_leak's check.ts does `import { type Check, ownedObjects } from "core"`.
    // If materialized under an OS tmpdir, this import throws
    // "Cannot find module 'core'" — the exact bug being regression-tested.
    const mod = await import(pathToFileURL(join(out, "check.ts")).href);
    expect(typeof mod.check).toBe("function");
  });
});
