import { describe, it, expect } from "vitest";
import {
  mkdtempSync,
  readFileSync,
  existsSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CorpusScore } from "core";
import { CostCollector, writeRunReport, type RunReport } from "./report.js";
import {
  perturbationGap,
} from "./report.js";
import type { RunManifest } from "../adapters/manifest.js";

const manifest: RunManifest = {
  sui_version: "sui 1.42.0", image_id: "sha256:x", node_version: "22.0.0",
  mysten_sui_version: "^2.15.0", git_commit: "abc1234",
};

describe("CostCollector", () => {
  it("sums per-entry costs into a total", () => {
    const c = new CostCollector();
    c.record("a", { turns: 2, inputTokens: 10, outputTokens: 5 });
    c.record("b", { turns: 3, inputTokens: 20, outputTokens: 7 });
    const cc = c.corpusCost();
    expect(cc.perEntry.a.turns).toBe(2);
    expect(cc.total).toEqual({ turns: 5, inputTokens: 30, outputTokens: 12 });
  });

  it("starts empty with a zero total", () => {
    expect(new CostCollector().corpusCost().total).toEqual({ turns: 0, inputTokens: 0, outputTokens: 0 });
  });
});

describe("writeRunReport", () => {
  it("rejects a non-empty output directory instead of mixing runs", () => {
    const dir = mkdtempSync(join(tmpdir(), "suibench-report-"));
    writeFileSync(join(dir, "stale-scorecard.json"), "{}");
    const score = {
      complete: true,
      scored: 0,
      errored: 0,
      micro: {},
      macro: {},
      entries: [],
      erroredEntries: [],
    } as unknown as CorpusScore;

    expect(() =>
      writeRunReport(
        dir,
        { score, cost: new CostCollector().corpusCost(), manifest },
        {
          axis: "comprehension",
          harness: "static",
          model: "m",
          judgeModel: "m",
          k: 1,
          concurrency: 1,
          maxTurns: 60,
          effort: "low",
          dataset: "/dataset",
          filter: null,
          policy: "live",
          requestedTargets: [],
          image: "suibench-auditor",
        },
      ),
    ).toThrow(/output directory is not empty/);
    expect(existsSync(join(dir, "manifest.json"))).toBe(false);
  });

  it("lays out manifest.json, corpus.json, and one scorecard.json per entry", () => {
    const dir = mkdtempSync(join(tmpdir(), "suibench-report-"));
    const score = {
      complete: false, scored: 1, errored: 1,
      micro: {} as CorpusScore["micro"], macro: {} as CorpusScore["macro"],
      entries: [{ target: "vault", run: { labels: [], findings: [], metrics: {} } }],
      erroredEntries: [{
        target: "broken",
        error: "AgentError: provider unavailable",
        attempts: 1,
      }],
    } as unknown as CorpusScore;
    const collector = new CostCollector();
    collector.record("broken", { turns: 2, inputTokens: 30, outputTokens: 4 });
    const report: RunReport<CorpusScore> = {
      score,
      cost: collector.corpusCost(),
      manifest,
    };
    writeRunReport(dir, report, {
      axis: "exploitation", harness: "harnessed", model: "claude-opus-4-8",
      judgeModel: "claude-opus-4-8", k: 1, concurrency: 3, maxTurns: 60,
      effort: "medium", dataset: "/dataset", filter: "vault", policy: "live",
      requestedTargets: ["vault"], image: "suibench-auditor",
    });

    expect(existsSync(join(dir, "manifest.json"))).toBe(true);
    const corpus = JSON.parse(readFileSync(join(dir, "corpus.json"), "utf-8"));
    expect(corpus.config.axis).toBe("exploitation");
    expect(corpus.config.concurrency).toBe(3);
    expect(corpus.config.maxTurns).toBe(60);
    expect(corpus.config.effort).toBe("medium");
    expect(corpus.config.policy).toBe("live");
    expect(corpus.config.requestedTargets).toEqual(["vault"]);
    expect(corpus.scored).toBe(1);
    expect(existsSync(join(dir, "entries", "vault", "scorecard.json"))).toBe(true);
    const errored = JSON.parse(
      readFileSync(join(dir, "entries", "broken", "scorecard.json"), "utf-8"),
    );
    expect(errored.error).toMatchObject({ target: "broken", attempts: 1 });
    expect(errored.cost).toMatchObject({ turns: 2 });
  });

  it("serializes bigint values without throwing", () => {
    const dir = mkdtempSync(join(tmpdir(), "suibench-report-"));
    const score = {
      complete: true, scored: 1, errored: 0, micro: {}, macro: {},
      entries: [{ target: "t", run: { big: 42n } }], erroredEntries: [],
    } as unknown as CorpusScore;
    expect(() =>
      writeRunReport(dir, { score, cost: new CostCollector().corpusCost(), manifest },
        {
          axis: "exploitation", harness: "static", model: "m", judgeModel: "m",
          k: 1, concurrency: 1, maxTurns: 60,
          effort: "low", dataset: "/dataset", filter: null, policy: "scripted",
          requestedTargets: ["t"], image: "suibench-auditor",
        }),
    ).not.toThrow();
    const card = readFileSync(join(dir, "entries", "t", "scorecard.json"), "utf-8");
    expect(card).toContain("42");
  });
});

describe("perturbation gap", () => {
  it("gap = original recall − mean(twin recalls); null-safe", () => {
    expect(perturbationGap(1, [0.5, 0.5]).gap).toBe(0.5);
    expect(perturbationGap(1, [1, 1]).gap).toBe(0);
    expect(perturbationGap(null, [1]).gap).toBeNull();
    expect(perturbationGap(1, [null, null]).gap).toBeNull();
  });
});
