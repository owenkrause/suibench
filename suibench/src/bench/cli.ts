#!/usr/bin/env node
// The eval CLI: run the bench over the dataset with a chosen policy + model +
// effort, print the CorpusScore.
//
//   suibench --dataset ./dataset --axis exploitation --model claude-opus-4-8
import { readdirSync, existsSync, statSync, realpathSync } from "node:fs";
import { resolve, join, basename } from "node:path";
import { fileURLToPath } from "node:url";
import type { JudgeFn, RunEnv } from "core";
import {
  AgentError,
  FileTrajectorySink,
  getModelClient,
  resolveModel,
  type EffortLevel,
  type ModelClient,
} from "core/runtime";
import { SandboxManager } from "../adapters/sandbox.js";
import { UNTRUSTED_IMAGE, CONFIRMER_IMAGE, GATE_IMAGE } from "../adapters/images.js";
import { Confirmer } from "../adapters/confirmer.js";
import { makeJudge } from "../adapters/judge.js";
import { loadEntry } from "../dataset/index.js";
import { captureManifest } from "../adapters/manifest.js";
import {
  bench,
  type Axis,
  type Harness,
  type BenchDeps,
  type RunConfig,
} from "./driver.js";
import { auditorRunFactory, patchRunFactory } from "./policies.js";
import { benchPatch } from "./patch-driver.js";
import { benchPerturb } from "./perturb-driver.js";
import { perturbationManifest } from "../adapters/manifest.js";
import { CostCollector, writeRunReport, type RunReport, type RunDirConfig } from "./report.js";
import type { CorpusScore } from "core";

export interface Args {
  dataset: string;
  filter?: string;
  axis: Axis;
  harness: Harness;
  model: string;
  judgeModel: string;
  effort: EffortLevel;
  k: number;
  concurrency: number;
  maxTurns: number;
  output: string;
  perturb: boolean;
  twinsPerEntry: number;
}

const VALUE_FLAGS = new Set([
  "--dataset",
  "--filter",
  "--axis",
  "--harness",
  "--model",
  "--judge-model",
  "--effort",
  "--k",
  "--concurrency",
  "--max-turns",
  "--output",
  "--twins-per-entry",
]);
const BOOLEAN_FLAGS = new Set(["--perturb"]);
const AXES = new Set(["comprehension", "exploitation", "patch"]);
const HARNESSES = new Set(["static", "harnessed"]);
const EFFORTS = new Set<EffortLevel>(["low", "medium", "high", "xhigh", "max"]);

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function positiveInteger(raw: string, flag: string): number {
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${flag} must be a positive integer; got "${raw}"`);
  }
  return value;
}

export function parseArgs(argv: string[]): Args {
  const values = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (BOOLEAN_FLAGS.has(flag)) continue;
    if (!VALUE_FLAGS.has(flag)) throw new Error(`unknown option "${flag}"`);
    if (values.has(flag)) throw new Error(`duplicate option "${flag}"`);
    const value = argv[++i];
    if (value === undefined || value.length === 0 || value.startsWith("--")) {
      throw new Error(`${flag} requires a value`);
    }
    values.set(flag, value);
  }
  const get = (flag: string): string | undefined => values.get(flag);

  const axisRaw = get("--axis") ?? "exploitation";
  if (!AXES.has(axisRaw)) throw new Error(`--axis must be comprehension, exploitation, or patch`);
  const axis = axisRaw as Axis;

  const harnessRaw = get("--harness") ?? "harnessed";
  if (!HARNESSES.has(harnessRaw)) throw new Error(`--harness must be static or harnessed`);
  const harness = harnessRaw as Harness;

  const effortRaw = get("--effort") ?? "medium";
  if (!EFFORTS.has(effortRaw as EffortLevel)) {
    throw new Error(`--effort must be low, medium, high, xhigh, or max`);
  }
  const effort = effortRaw as EffortLevel;

  const model = get("--model") ?? "claude-opus-4-8";
  const judgeModel = get("--judge-model") ?? "claude-opus-4-8";
  const modelEntry = resolveModel(model);
  resolveModel(judgeModel);
  if (
    modelEntry.validEfforts.length > 0 &&
    !modelEntry.validEfforts.includes(effort)
  ) {
    throw new Error(
      `model "${model}" does not support --effort ${effort}; valid: ${modelEntry.validEfforts.join(", ")}`,
    );
  }

  return {
    dataset: get("--dataset") ?? resolve(import.meta.dirname, "../../dataset"),
    filter: get("--filter"),
    axis,
    harness,
    model,
    judgeModel,
    effort,
    k: positiveInteger(get("--k") ?? "1", "--k"),
    concurrency: positiveInteger(get("--concurrency") ?? "3", "--concurrency"),
    maxTurns: positiveInteger(get("--max-turns") ?? "60", "--max-turns"),
    output: get("--output") ?? `.suibench/${timestamp()}`,
    perturb: argv.includes("--perturb"),
    twinsPerEntry: positiveInteger(get("--twins-per-entry") ?? "3", "--twins-per-entry"),
  };
}

/** Dataset entry dirs: those with an entry.json under `dataset`, filtered by name. */
function discoverEntries(datasetDir: string, filter?: string): string[] {
  const root = resolve(datasetDir);
  if (!existsSync(root)) throw new Error(`no dataset dir at ${root}`);
  return readdirSync(root)
    .map((name) => join(root, name))
    .filter(
      (dir) =>
        statSync(dir).isDirectory() && existsSync(join(dir, "entry.json")),
    )
    .filter((dir) => !filter || basename(dir).includes(filter))
    .sort((a, b) => basename(a).localeCompare(basename(b)));
}

export function lazyJudge(
  model: string,
  clientFor: (model: string) => ModelClient = getModelClient,
): JudgeFn {
  let judge: JudgeFn | undefined;
  return async (finding, candidates) => {
    if (!judge) {
      try {
        judge = makeJudge(clientFor(model), model);
      } catch (err) {
        if (err instanceof AgentError) throw err;
        throw new AgentError(
          `judge setup failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return judge(finding, candidates);
  };
}

export async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const entryDirs = discoverEntries(args.dataset, args.filter);
  if (entryDirs.length === 0) {
    console.error("no entries matched");
    process.exit(1);
  }

  const env: RunEnv = {
    model: args.model,
    effort: args.effort,
  };
  const config: RunConfig = {
    harness: args.harness,
    axis: args.axis,
    env,
    k: args.k,
  };
  console.error(
    `[bench] ${args.model} · reasoning=${resolveModel(args.model).reasoning} · effort=${args.effort} · axis=${args.axis} · k=${args.k} · concurrency=${args.concurrency}`,
  );

  const manager = new SandboxManager();
  const manifest = await captureManifest({ untrusted: UNTRUSTED_IMAGE, confirmer: CONFIRMER_IMAGE, gate: GATE_IMAGE });
  const collector = new CostCollector();
  const sink = new FileTrajectorySink(join(args.output, "trajectories"));
  const runDirConfig: RunDirConfig = {
    axis: args.axis,
    harness: args.harness,
    model: args.model,
    judgeModel: args.judgeModel,
    k: args.k,
    concurrency: args.concurrency,
    maxTurns: args.maxTurns,
    effort: args.effort,
    dataset: resolve(args.dataset),
    filter: args.filter ?? null,
    requestedTargets: entryDirs.map((dir) => basename(dir)),
    images: { untrusted: UNTRUSTED_IMAGE, confirmer: CONFIRMER_IMAGE, gate: GATE_IMAGE },
  };

  // Perturb mode: score originals + regenerated twins, report the recall gap.
  // Confirmed-tier recall is the perturbation signal, so it requires the
  // Confirmer (--axis exploitation).
  if (args.perturb) {
    if (args.axis !== "exploitation") {
      console.error("--perturb requires --axis exploitation (confirmed-tier recall)");
      process.exit(1);
    }
    const twinDumpDir = join(args.output, "twins");
    const perturbDeps: BenchDeps = {
      runFor: auditorRunFactory({
        manager,
        model: args.model,
        effort: args.effort,
        maxTurns: args.maxTurns,
      }),
      graderFor: (entry) => new Confirmer(manager, entry.harness),
      concurrency: args.concurrency,
      onEntryCost: (target, cost) => collector.record(target, cost),
      sink,
    };
    try {
      const perturbation = await benchPerturb(entryDirs, config, perturbDeps, {
        twinsPerEntry: args.twinsPerEntry,
        twinDumpDir,
        concurrency: args.concurrency,
      });
      const report: RunReport<CorpusScore> = {
        score: {
          complete: perturbation.complete,
          scored: perturbation.scored,
          errored: perturbation.errored,
          micro: {} as CorpusScore["micro"],
          macro: {} as CorpusScore["macro"],
          entries: [],
          erroredEntries: perturbation.erroredEntries,
        },
        cost: collector.corpusCost(),
        manifest: { ...manifest, perturbation: perturbationManifest(args.twinsPerEntry) },
        perturbation,
      };
      writeRunReport(args.output, report, runDirConfig);
      console.log(JSON.stringify(perturbation, bigintReplacer, 2));
      console.error(`\n[perturb] macro_gap=${perturbation.macro_gap} — twins + perturbation.json under ${args.output}`);
      if (!perturbation.complete) {
        const names = perturbation.erroredEntries.map((entry) => entry.target).join(", ");
        console.error(
          `\n[perturb] INCOMPLETE — ${perturbation.scored}/${perturbation.scored + perturbation.errored} scored, ${perturbation.errored} errored: ${names}`,
        );
        console.error(
          `        aggregate reflects SCORED entries only; rerun errored before trusting it`,
        );
        process.exitCode = 2;
      }
    } finally {
      await manager.teardownAll();
    }
    return;
  }

  // Patch mode is its own vertical (benchPatch), not a bench axis.
  if (args.axis === "patch") {
    try {
      const score = await benchPatch(entryDirs, env, args.k, args.harness, {
        manager,
        patchFor: patchRunFactory({
          manager,
          model: args.model,
          effort: args.effort,
          maxTurns: args.maxTurns,
        }),
        concurrency: args.concurrency,
        onEntryCost: (target, cost) => collector.record(target, cost),
        sink,
      });
      const report: RunReport<typeof score> = { score, cost: collector.corpusCost(), manifest };
      writeRunReport(args.output, report, runDirConfig);
      console.log(JSON.stringify(score, bigintReplacer, 2));
      console.error(`\n[patch] wrote run report to ${args.output}`);
      if (!score.complete) {
        const names = score.erroredEntries.map((e) => e.target).join(", ");
        console.error(
          `\n[patch] INCOMPLETE — ${score.scored}/${score.scored + score.errored} scored, ${score.errored} errored: ${names}`,
        );
        process.exitCode = 2;
      }
    } finally {
      await manager.teardownAll();
    }
    return;
  }

  const deps: BenchDeps = {
    runFor: auditorRunFactory({
      manager,
      model: args.model,
      effort: args.effort,
      maxTurns: args.maxTurns,
    }),
    concurrency: args.concurrency,
    onEntryCost: (target, cost) => collector.record(target, cost),
    sink,
  };

  // Axis grader: exploitation needs the Confirmer; comprehension needs a judge.
  // The Confirmer is built per-entry so it carries that entry's setup/victim
  // harness (funding, the legit victim op) — the phases the check depends on.
  if (args.axis === "exploitation") {
    deps.graderFor = (entry) => new Confirmer(manager, entry.harness);
  } else {
    // Construct the judge client only if a finding actually needs matching.
    deps.judge = lazyJudge(args.judgeModel);
  }

  try {
    const score = await bench(entryDirs, config, deps);
    const report: RunReport<typeof score> = { score, cost: collector.corpusCost(), manifest };
    writeRunReport(args.output, report, runDirConfig);
    console.log(JSON.stringify(score, bigintReplacer, 2));
    console.error(`\n[bench] wrote run report to ${args.output}`);
    if (!score.complete) {
      const names = score.erroredEntries.map((e) => e.target).join(", ");
      console.error(
        `\n[bench] INCOMPLETE — ${score.scored}/${score.scored + score.errored} scored, ${score.errored} errored: ${names}`,
      );
      console.error(
        `        aggregate reflects SCORED entries only; rerun errored before trusting it`,
      );
      process.exitCode = 2;
    }
  } finally {
    await manager.teardownAll();
  }
}

function bigintReplacer(_k: string, v: unknown): unknown {
  return typeof v === "bigint" ? v.toString() : v;
}

const invokedPath = process.argv[1];
let invokedDirectly = false;
if (invokedPath) {
  try {
    invokedDirectly =
      realpathSync(invokedPath) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    /* an unresolved argv path cannot be this module */
  }
}
if (invokedDirectly) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
