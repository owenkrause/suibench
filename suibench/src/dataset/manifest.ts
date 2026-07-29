// The `entry.json` manifest: the machine-readable labels + provenance for one
// dataset entry. Replaces the legacy `groundtruth.json`. Each vuln carries an
// explicit `id` (a rename-safe UID, NOT derived from title/filename) that keys
// `exploits/<id>.ts` and `patches/<id>/` — so no slugify/handle logic exists.
import type { Severity, Harm } from "core";

/** One labeled vulnerability in an entry's manifest. */
export interface ManifestVuln {
  /** Stable UID; keys the exploit + patch dirs and the attribution join. */
  id: string;
  module: string;
  title: string;
  severity: Severity;
  root_cause: string;
  /** Harm modality; defaults to "state" when absent. */
  harm?: Harm;
  /** True iff the entry ships `exploits/<id>.ts` (confirmed-tier for this vuln). */
  exploit?: boolean;
  /** True iff the entry ships `patches/<id>/` (attribution-ready). */
  patch?: boolean;
}

export interface Manifest {
  /** Dataset schema version — bump on a breaking layout change. */
  version?: number;
  vulns: ManifestVuln[];
}

const SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low"]);
const HARMS = new Set<Harm>(["state", "availability"]);

/** Parse + validate raw `entry.json` text into a typed `Manifest`. Throws with a
 *  precise message on any shape violation — a dataset entry is a dataset record,
 *  so a malformed manifest is a hard error, not a silent skip. */
export function parseManifest(raw: string, where: string): Manifest {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (e) {
    throw new Error(`${where}: invalid JSON — ${(e as Error).message}`);
  }
  const obj = json as Record<string, unknown>;
  if (!obj || typeof obj !== "object" || !Array.isArray(obj.vulns)) {
    throw new Error(`${where}: manifest must have a "vulns" array`);
  }
  const vulns = obj.vulns.map((v, i) => parseVuln(v, `${where} vulns[${i}]`));
  assertUniqueIds(vulns, where);
  const manifest: Manifest = { vulns };
  if (obj.version !== undefined) {
    if (typeof obj.version !== "number")
      throw new Error(`${where}: "version" must be a number`);
    manifest.version = obj.version;
  }
  return manifest;
}

function parseVuln(v: unknown, where: string): ManifestVuln {
  const o = v as Record<string, unknown>;
  const str = (k: string): string => {
    const val = o[k];
    if (typeof val !== "string" || val.length === 0)
      throw new Error(`${where}: "${k}" must be a non-empty string`);
    return val;
  };
  const severity = str("severity") as Severity;
  if (!SEVERITIES.has(severity))
    throw new Error(`${where}: invalid severity "${severity}"`);
  const vuln: ManifestVuln = {
    id: str("id"),
    module: str("module"),
    title: str("title"),
    severity,
    root_cause: str("root_cause"),
  };
  if (o.harm !== undefined) {
    if (!HARMS.has(o.harm as Harm))
      throw new Error(`${where}: invalid harm "${String(o.harm)}"`);
    vuln.harm = o.harm as Harm;
  }
  if (o.exploit !== undefined) vuln.exploit = Boolean(o.exploit);
  if (o.patch !== undefined) vuln.patch = Boolean(o.patch);
  return vuln;
}

function assertUniqueIds(vulns: ManifestVuln[], where: string): void {
  const seen = new Set<string>();
  for (const { id } of vulns) {
    if (seen.has(id)) throw new Error(`${where}: duplicate vuln id "${id}"`);
    seen.add(id);
  }
}
