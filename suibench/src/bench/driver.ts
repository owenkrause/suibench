// The bench driver — the thin assembly that turns the parts (dataset + adapters +
// kernel combinators) into a runnable eval. It generalizes the controls prototype
// (`controls/harness.ts::runAndGrade`) over the REAL Confirmer, real dataset
// entries, and the two independently-selectable axes.
//
// A run config is (harness ∈ {static, harnessed}) × (axis ∈ {comprehension,
// exploitation}). The two dimensions are orthogonal:
//   - harness  picks HOW the policy sees the target (source inlined = static, or
//              a live sandbox = harnessed). That's the policy's construction — the
//              driver only consumes the reported findings/exploits.
//   - axis     picks HOW those reports are graded: comprehension = the LLM judge
//              over findings↔labels (scoreDetect); exploitation = the deterministic
//              counterfactual (Confirmer + attribution + scoreConfirmed).
//
// Least-privilege: the Observation carries ONLY `loadSource(entry)` (Move.toml +
// sources/). The groundtruth / check / reference exploits / patches live in the
// dataset dir and NEVER flow into the Observation or any Mount — see
// `buildObservation` and the `sanitize`-gated mount seam.
import type {
  Policy,
  Grader,
  Observation,
  ToolMenu,
  RunEnv,
  Exploit,
  Finding,
  RunScore,
  EntryScore,
  CorpusScore,
  ErroredEntry,
  ExploitRun,
  MoveFile,
  JudgeFn,
  Store,
  Trajectory,
} from "core";
import {
  runCounterfactuals,
  attribute,
  scoreConfirmed,
  scoreDetect,
  aggregateCorpus,
  passK,
} from "core";
import type { CostMeter, CostTotals } from "core/runtime";
import { AgentError, CostMeter as CostMeterCtor } from "core/runtime";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { basename, join as pjoin } from "node:path";
import { tmpdir } from "node:os";
import { collectReports } from "../controls/harness.js";
import { boundedMap } from "../util/bounded.js";
import {
  counterfactualBoundary,
  type PatchedLabel,
} from "../adapters/counterfactual-boundary.js";
import { InfraError } from "../adapters/confirmer.js";
import {
  loadEntry,
  loadCheck,
  loadSource,
  loadPatchFiles,
  type DatasetEntry,
} from "../dataset/index.js";

/** Where the policy sees the target from. */
export type Harness = "static" | "harnessed";
/**
 * Which grader decides the score. Kept as an open string set, NOT a closed
 * detect/confirmed binary: a `patch` axis (kernel `gradePatch` + its future
 * effectful adapter) slots in as a third `GradingStrategy` with no dispatch
 * surgery here — see `STRATEGIES`.
 */
export type Axis = "comprehension" | "exploitation" | (string & {});

export interface RunConfig {
  harness: Harness;
  axis: Axis;
  env: RunEnv;
  /** k for pass@k (default 1). */
  k?: number;
}

/** Everything the driver needs to grade one entry, minus the config. A `Policy`
 *  is produced per-entry (it wraps that entry's Observation/sandbox), so the
 *  caller injects a FACTORY, not a shared instance. */
export interface BenchDeps {
  /** Builds the policy for one entry's Observation. The AuditorPolicy wires its
   *  own Sandbox over the SAME sanitized source; a scripted/replay policy ignores
   *  it. Kept a factory so pass@k re-runs get a fresh policy each attempt. The
   *  injected `meter` (when present) is the entry's cost accumulator — the
   *  AuditorPolicy folds token usage into it; scripted/replay policies ignore it. */
  policyFor: (entry: DatasetEntry, observation: Observation, meter?: CostMeter) => Policy;
  /** Builds the exploitation-axis grader for ONE entry. A factory, not a shared
   *  instance, because the confirmer's setup/victim phases are per-entry data
   *  (`entry.harness`) — a shared grader would run every entry with an empty
   *  harness, so seeded and availability entries would mis-grade. Required for
   *  the exploitation axis; unused on comprehension. */
  graderFor?: (entry: DatasetEntry) => Grader;
  /** The comprehension-axis judge (findings↔labels). Required for that axis. */
  judge?: JudgeFn;
  /** Optional trajectory sink so a run replays offline. */
  store?: Store;
  /** Extra/override grading strategies, merged over the built-in `STRATEGIES`.
   *  A future `patch` axis registers here with no driver change. */
  strategies?: Record<string, GradingStrategy>;
  /** Max entries graded concurrently (default 1). pass@k stays sequential. */
  concurrency?: number;
  /** Called once per attempted entry with its accumulated cost. */
  onEntryCost?: (target: string, cost: CostTotals) => void;
}

const DEFAULT_TOOLS: ToolMenu = { bash: true, writeFile: true, references: true };
// Static arm = naked model: no live tools AND no reference library, pure
// reasoning over inlined source. `writeFile` is its inert output channel for
// findings.json; Sandbox.writeFile has no shell/execution path.
const STATIC_TOOLS: ToolMenu = { bash: false, writeFile: true, references: false };

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive integer; got ${value}`);
  }
}

function assertValidRunConfig(config: RunConfig): void {
  assertPositiveInteger(config.k ?? 1, "k");
  if (config.axis === "exploitation" && config.harness === "static") {
    throw new Error(
      "static + exploitation is invalid: the static policy cannot produce executed exploits",
    );
  }
}

/** Build the model-facing Observation. The source is the ONLY channel: it is the
 *  sanitized package, minted by `loadSource`, with no groundtruth attached. */
function buildObservation(
  entry: DatasetEntry,
  config: RunConfig,
): Observation {
  return {
    source: loadSource(entry),
    tools: config.harness === "static" ? STATIC_TOOLS : DEFAULT_TOOLS,
    env: config.env,
  };
}

/** Read a reference/exploit script into an in-container `MoveFile`. */
function readScriptFile(path: string): MoveFile {
  return { path: basename(path), contents: readFileSync(path, "utf-8") };
}

/** What a grading strategy is handed after the policy has run: the entry, the
 *  collected reports, and the injected deps. It returns the leaf `RunScore`. A
 *  new axis (e.g. `patch`) is just another entry in `STRATEGIES` — no `if/else`. */
export interface GradeInput {
  entry: DatasetEntry;
  exploits: Exploit[];
  findings: Finding[];
  deps: BenchDeps;
}
export type GradingStrategy = (input: GradeInput) => Promise<RunScore>;

/**
 * The axis registry: `axis` string -> strategy. The driver dispatches through
 * this map, so the detect/confirmed pair is not a hardcoded binary — a `patch`
 * strategy (kernel `gradePatch` + its adapter) registers here later untouched.
 */
export const STRATEGIES: Record<string, GradingStrategy> = {
  comprehension: async ({ entry, findings, deps }) => {
    if (!deps.judge) throw new Error("comprehension axis requires a judge");
    return scoreDetect(findings, entry.groundtruth, deps.judge);
  },
  exploitation: async ({ entry, exploits, findings, deps }) => {
    if (!deps.graderFor) throw new Error("exploitation axis requires a grader");
    if (entry.tier !== "confirmed")
      throw new Error(
        `${entry.target}: exploitation axis needs a confirmed-tier entry (has check.ts)`,
      );
    // Built per-entry so the confirmer carries THIS entry's setup/victim harness.
    return gradeExploitation(entry, exploits, findings, deps.graderFor(entry));
  },
};

/**
 * Grade one entry on the EXPLOITATION axis: run each reported exploit through the
 * real Confirmer + counterfactual attribution + `scoreConfirmed`. This is the
 * prototype's `runAndGrade` loop with the real Confirmer and the real
 * `counterfactualBoundary` adapter (which owns the variant-mount overlay), so the
 * driver never reimplements the N+1 counterfactual — it composes the kernel.
 */
async function gradeExploitation(
  entry: DatasetEntry,
  exploits: Exploit[],
  findings: Finding[],
  grader: Grader,
): Promise<RunScore> {
  const check = await loadCheck(entry);
  const vulnerableMount = loadSource(entry);

  // Labels the counterfactual attributes against: each manifest vuln with a patch.
  const labels: PatchedLabel[] = entry.manifest.vulns
    .filter((v) => entry.patches[v.id])
    .map((v) => ({ id: v.id, patchFiles: loadPatchFiles(entry, v.id) }));

  const runs: ExploitRun[] = [];
  for (const exploit of exploits) {
    // Each exploit gets its OWN boundary so `baseProof` doesn't cross-contaminate.
    // The grader hands the per-boot CheckParams back WITH each delta, so the
    // boundary needs no static params and the driver stays on the `Grader` port.
    const { boundary } = counterfactualBoundary({
      grader,
      vulnerableMount,
      readScript: readScriptFile,
      check,
      label: entry.target,
    });
    const run = await runCounterfactuals(
      entry.dir,
      exploit.finding.id,
      // The Confirmer re-runs the model's OWN exploit script, not a dataset path.
      writeExploitTmp(exploit.script),
      labels,
      boundary,
    );
    runs.push(run);
  }

  const attribution = attribute(runs);
  return scoreConfirmed(findings, entry.groundtruth, attribution);
}

// The boundary's `readScript` reads a path; the model's exploit is already a
// MoveFile (contents in hand), so stash it to a tmp file and hand back the path.
const _tmpDirs: string[] = [];
function writeExploitTmp(script: MoveFile): string {
  const dir = mkdtempSync(pjoin(tmpdir(), "suibench-exploit-"));
  _tmpDirs.push(dir);
  const p = pjoin(dir, basename(script.path) || "exploit.mts");
  writeFileSync(p, script.contents);
  return p;
}
/** Remove exploit tmp files after a corpus run. */
export function cleanupExploitTmp(): void {
  for (const d of _tmpDirs.splice(0)) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
}

/**
 * Grade ONE run of ONE entry: collect the policy's reports, then dispatch to the
 * axis's `GradingStrategy`. This is the leaf `Task` the `passK` combinator
 * re-runs. `deps.strategies` overrides/extends the built-in `STRATEGIES` (that's
 * where a future `patch` axis plugs in).
 */
export async function runEntryOnce(
  entry: DatasetEntry,
  config: RunConfig,
  deps: BenchDeps,
  meter?: CostMeter,
): Promise<RunScore> {
  assertValidRunConfig(config);
  const observation = buildObservation(entry, config);
  const policy = deps.policyFor(entry, observation, meter);
  const { exploits, findings } = await collectReports(policy, observation);

  if (deps.store) await recordTrajectory(deps.store, entry, observation, policy);

  const strategy = { ...STRATEGIES, ...deps.strategies }[config.axis];
  if (!strategy) throw new Error(`unknown grading axis "${config.axis}"`);
  return strategy({ entry, exploits, findings, deps });
}

// A minimal trajectory: the single Observation the policy graded + a terminal
// marker. (The real per-turn trace lives inside the AuditorPolicy; the Store
// records the driver-visible reports so a run replays offline.)
async function recordTrajectory(
  store: Store,
  entry: DatasetEntry,
  observation: Observation,
  _policy: Policy,
): Promise<void> {
  const trajectory: Trajectory = {
    id: `${entry.target}-${Date.now()}`,
    target: entry.target,
    steps: [{ observation, action: { kind: "run_bash", command: ":" } }],
  };
  await store.record(trajectory);
}

/** runs → entry, via the kernel `passK`. `k=1` is a single run (no passk field). */
export async function benchEntry(
  entry: DatasetEntry,
  config: RunConfig,
  deps: BenchDeps,
  meter?: CostMeter,
): Promise<EntryScore> {
  return passK(
    config.k ?? 1,
    entry,
    entry.target,
    (e) => runEntryOnce(e, config, deps, meter),
  );
}

/**
 * The corpus driver: grade every entry dir, roll up with `aggregateCorpus`
 * (micro/macro). Entry dirs are loaded via `loadEntry`; the config + deps are
 * shared. Returns a `CorpusScore`.
 */
export async function bench(
  entryDirs: string[],
  config: RunConfig,
  deps: BenchDeps,
): Promise<CorpusScore> {
  assertValidRunConfig(config);
  type Outcome =
    | { ok: true; score: EntryScore }
    | { ok: false; errored: ErroredEntry };

  // Exploitation grades via the deterministic check.ts oracle; a detect-tier
  // entry has none, so it is not gradeable on this axis. Exclude (not error) it
  // — logged, kept out of the aggregate — so a mixed-corpus run scores the
  // confirmed-tier entries instead of aborting on the first detect-tier one.
  const loaded = entryDirs.map(loadEntry).filter((entry) => {
    if (config.axis === "exploitation" && entry.tier !== "confirmed") {
      console.error(
        `[bench] ${entry.target}: SKIPPED — not gradeable on the exploitation axis (no check.ts)`,
      );
      return false;
    }
    return true;
  });
  try {
    const outcomes = await boundedMap(
      loaded,
      deps.concurrency ?? 1,
      async (entry): Promise<Outcome> => {
        const meter = new CostMeterCtor();
        try {
          try {
            const score = await benchEntry(entry, config, deps, meter);
            return { ok: true, score };
          } catch (err) {
            // Boundary/model infrastructure failures isolate to this entry. A
            // different throw is a real defect and still aborts the run.
            if (!(err instanceof InfraError) && !(err instanceof AgentError)) throw err;
            console.error(
              `[bench] ${entry.target}: ERRORED — excluded from aggregate, rerun to complete`,
            );
            return {
              ok: false,
              errored: {
                target: entry.target,
                error: `${err.name}: ${err.message}`,
                attempts: err.attempts,
              },
            };
          }
        } finally {
          deps.onEntryCost?.(entry.target, meter.totals());
        }
      },
    );

    const entries = outcomes
      .filter((o): o is { ok: true; score: EntryScore } => o.ok)
      .map((o) => o.score);
    const errored = outcomes
      .filter((o): o is { ok: false; errored: ErroredEntry } => !o.ok)
      .map((o) => o.errored);
    return aggregateCorpus(entries, errored);
  } finally {
    cleanupExploitTmp();
  }
}

/**
 * The harness-ablation sweep: grade the SAME corpus + judge under static vs
 * harnessed, both on the comprehension axis. The gap between the two macro
 * recalls isolates the harness's contribution (does live tooling find bugs a
 * static read misses?). Both arms share the axis so the number is comparable.
 */
export interface SweepResult {
  static: CorpusScore;
  harnessed: CorpusScore;
  /** harnessed macro recall − static macro recall. */
  harnessGap: number;
}

export async function sweep(
  entryDirs: string[],
  base: Omit<RunConfig, "harness" | "axis">,
  deps: BenchDeps,
): Promise<SweepResult> {
  const axis: Axis = "comprehension";
  const staticScore = await bench(
    entryDirs,
    { ...base, harness: "static", axis },
    deps,
  );
  const harnessedScore = await bench(
    entryDirs,
    { ...base, harness: "harnessed", axis },
    deps,
  );
  return {
    static: staticScore,
    harnessed: harnessedScore,
    harnessGap:
      (harnessedScore.macro.recall ?? 0) - (staticScore.macro.recall ?? 0),
  };
}
