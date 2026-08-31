import { describe, it, expect } from "vitest";
import type { RunScore } from "core";
import {
  evaluateGrade,
  buildReferenceExploits,
  datasetEntryDirs,
  verifyDatasetEntryDir,
} from "./verify-graders.js";
import type { DatasetEntry } from "../src/dataset/index.js";
import type { SandboxManager } from "../src/adapters/sandbox.js";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function run(over: Partial<RunScore["metrics"]>): RunScore {
  return {
    labels: [{
      id: "label-1",
      title: "label",
      severity: "critical",
      harm: "state",
      status: "HIT",
      matched_finding: "finding-1",
      severity_correct: true,
    }],
    findings: [{
      id: "finding-1",
      title: "finding",
      classification: "TP",
      matched_label: "label-1",
      confirmed: true,
    }],
    metrics: {
      tier: "confirmed",
      labels_total: 1, labels_hit: 1,
      findings_total: 1, true_positives: 1, false_positives: 0,
      unattributed_findings: 0,
      recall: 1, precision: 1, attribution_rate: 1,
      severity_accuracy: 1, severity_correct: 1, severity_total: 1,
      ...over,
    },
  } as RunScore;
}

describe("evaluateGrade", () => {
  it("passes a perfect confirmed grade", () => {
    expect(evaluateGrade(run({})).pass).toBe(true);
  });
  it("fails when a label was missed", () => {
    const r = evaluateGrade(run({ labels_hit: 0, recall: 0 }));
    expect(r.pass).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/label/i);
  });
  it("fails on a false positive", () => {
    const r = evaluateGrade(run({ findings_total: 2, false_positives: 1, precision: 0.5 }));
    expect(r.pass).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/false positive/i);
  });
  it("fails on an unattributed finding", () => {
    const r = evaluateGrade(run({
      findings_total: 2,
      unattributed_findings: 1,
      attribution_rate: 0.5,
    }));
    expect(r.pass).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/unattributed/i);
  });
  it("fails when there were no labels to hit", () => {
    expect(evaluateGrade(run({ labels_total: 0, labels_hit: 0, recall: null })).pass).toBe(false);
  });
  it("fails a detect-tier score even when its aggregate metrics look perfect", () => {
    const r = evaluateGrade(run({ tier: "detect" }));
    expect(r.pass).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/confirmed tier/i);
  });
  it("checks the concrete label and finding results, not only aggregate metrics", () => {
    const inconsistent = run({});
    inconsistent.labels[0].status = "MISS";
    inconsistent.findings[0].confirmed = false;
    const r = evaluateGrade(inconsistent);
    expect(r.pass).toBe(false);
    expect(r.reasons.join(" ")).toMatch(/not HIT/i);
    expect(r.reasons.join(" ")).toMatch(/not confirmed/i);
  });
  it.each([
    ["recall", { recall: 0 }],
    ["precision", { precision: 0 }],
    ["severity", { severity_accuracy: 0, severity_correct: 0 }],
  ])("fails when the derived %s metric is not perfect", (_name, metrics) => {
    expect(evaluateGrade(run(metrics)).pass).toBe(false);
  });
});

describe("buildReferenceExploits", () => {
  it("emits one exploit per exploit id, carrying the committed script", () => {
    const entry = {
      target: "vault",
      manifest: { vulns: [{ id: "admincap-leak", module: "vault", title: "t", severity: "critical", harm: "state", root_cause: "rc" }] },
      exploits: { "admincap-leak": makeTmpExploit() },
    } as unknown as DatasetEntry;
    const exploits = buildReferenceExploits(entry);
    expect(exploits).toHaveLength(1);
    expect(exploits[0].finding.id).toBe("admincap-leak");
    expect(exploits[0].script.contents).toContain("attack");
  });
});

describe("dataset gate discovery", () => {
  it("discovers an entry declared confirmed even when check.ts is missing", () => {
    const { root, dir } = makeEntry(validManifest({ exploit: true, patch: true }));
    try {
      expect(datasetEntryDirs(root)).toEqual([dir]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("reports missing confirmed assets instead of silently shrinking the gate", async () => {
    const { root, dir } = makeEntry(validManifest({ exploit: true, patch: true }));
    try {
      const result = await verifyDatasetEntryDir(dir, verifyDeps());
      expect(result).toMatchObject({ target: "candidate", pass: false });
      expect(result?.reasons.join(" ")).toMatch(/check\.ts/);
      expect(result?.reasons.join(" ")).toMatch(/reference exploit/);
      expect(result?.reasons.join(" ")).toMatch(/counterfactual patch/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("turns an ordinary manifest error into an entry failure", async () => {
    const { root, dir } = makeEntry("{not json");
    try {
      const result = await verifyDatasetEntryDir(dir, verifyDeps());
      expect(result).toMatchObject({ target: "candidate", pass: false });
      expect(result?.reasons.join(" ")).toMatch(/invalid JSON/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

function makeTmpExploit(): string {
  const p = join(mkdtempSync(join(tmpdir(), "vg-")), "admincap-leak.ts");
  writeFileSync(p, "export async function attack(ctx){}");
  return p;
}

function validManifest(flags: { exploit: boolean; patch: boolean }): string {
  return JSON.stringify({
    id: "chal_00000002",
    version: 1,
    vulns: [{
      id: "vuln-1",
      module: "candidate",
      title: "candidate",
      severity: "critical",
      harm: "state",
      root_cause: "root cause",
      ...flags,
    }],
  });
}

function makeEntry(manifest: string): { root: string; dir: string } {
  const root = mkdtempSync(join(tmpdir(), "verify-graders-"));
  const dir = join(root, "candidate");
  mkdirSync(dir);
  writeFileSync(join(dir, "entry.json"), manifest);
  return { root, dir };
}

function verifyDeps() {
  return {
    manager: {} as SandboxManager,
    env: { model: "none", effort: "low" } as const,
  };
}
