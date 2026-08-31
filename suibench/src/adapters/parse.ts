// suibench's own findings.json/patch.json -> {Exploit[]/MoveFile[]} parsers.
// core/runtime's runAgentLoop parses nothing, so each consumer owns turning what
// the model left in the sandbox into its own result shape. Mirrors suixploit's
// src/parse.ts, but parseReports also returns `findings` — the shape the bench
// driver hands to its grading strategies.
import { SandboxFileNotFoundError } from "core";
import type { Exploit, Finding, MoveFile, Sandbox, Severity } from "core";
import { AgentError } from "core/runtime";

/** A parsed row of the model's findings.json. */
interface RawFinding {
  id?: unknown;
  module?: unknown;
  severity?: unknown;
  title?: unknown;
  description?: unknown;
  exploitScript?: unknown;
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

/**
 * Read a text file out of the sandbox, or null when it is genuinely absent.
 * Any other `copyOut` failure (e.g. a container dying mid-read) is wrapped in
 * `AgentError` so the bench driver's per-entry isolation (`InfraError` /
 * `AgentError`) catches it, rather than a raw throw aborting the whole run.
 */
async function readSandboxFile(
  sandbox: Sandbox,
  path: string,
): Promise<string | null> {
  try {
    const buf = await sandbox.copyOut(path);
    return buf.toString("utf-8");
  } catch (err) {
    if (err instanceof SandboxFileNotFoundError) return null;
    throw new AgentError(
      `sandbox read failed for ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/** The runnable exploit artifact for a finding — a `MoveFile` the confirmer re-runs. */
async function readExploitScript(
  sandbox: Sandbox,
  row: RawFinding,
): Promise<MoveFile> {
  const name =
    typeof row.exploitScript === "string" && row.exploitScript.length > 0
      ? basename(row.exploitScript)
      : `exploit-${String(row.id ?? "unknown")}.mts`;
  const contents = (await readSandboxFile(sandbox, name)) ?? "";
  return { path: name, contents };
}

/**
 * Read the model-authored `findings.json` out of `sandbox` and turn each row
 * into an `Exploit`, mirroring `findings` off the same list (`findings =
 * exploits.map(e => e.finding)`) to match the driver's `runFor` shape. Missing
 * `findings.json` or malformed/non-array JSON both yield empty
 * results rather than throwing — an audit run that produced nothing readable
 * is a zero-finding result, not an error. A row with no string `id` is dropped.
 */
export async function parseReports(
  sandbox: Sandbox,
): Promise<{ exploits: Exploit[]; findings: Finding[] }> {
  const raw = await readSandboxFile(sandbox, "findings.json");
  if (!raw) return { exploits: [], findings: [] };
  let rows: RawFinding[];
  try {
    const parsed = JSON.parse(raw);
    rows = Array.isArray(parsed) ? (parsed as RawFinding[]) : [];
  } catch {
    return { exploits: [], findings: [] };
  }

  const exploits: Exploit[] = [];
  for (const row of rows) {
    const finding = toFinding(row);
    if (!finding) continue;
    const script = await readExploitScript(sandbox, row);
    exploits.push({ finding, script });
  }
  return { exploits, findings: exploits.map((e) => e.finding) };
}

/**
 * Read the model-authored `patch.json` (`{ patchedSources: [...] }`) out of
 * `sandbox` and each named rewritten source file, returning the corrected
 * sources (basename paths) for the driver to overlay. Missing/malformed
 * `patch.json`, a missing/non-array `patchedSources`, and a named source that
 * isn't actually in the sandbox all yield `[]`/are skipped rather than
 * throwing.
 */
export async function parsePatch(sandbox: Sandbox): Promise<MoveFile[]> {
  const raw = await readSandboxFile(sandbox, "patch.json");
  if (!raw) return [];
  let names: string[];
  try {
    const parsed = JSON.parse(raw) as { patchedSources?: unknown };
    names = Array.isArray(parsed.patchedSources)
      ? parsed.patchedSources.filter((n): n is string => typeof n === "string")
      : [];
  } catch {
    return [];
  }

  const files: MoveFile[] = [];
  for (const name of names) {
    const base = basename(name);
    // Patch mode rewrites sources under target/sources/ in the sandbox; the
    // returned MoveFile.path stays the basename — the driver overlays by it.
    const contents = await readSandboxFile(sandbox, `target/sources/${base}`);
    if (contents !== null) files.push({ path: base, contents });
  }
  return files;
}
