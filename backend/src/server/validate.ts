// Request-only shape validation for POST /api/benchmark/submissions. Version
// match and entry existence are enforced downstream by submitGrade — this is
// deliberately not adversarial hardening (no duplicate-id checks etc.), just
// enough to reject malformed bodies before they hit the DB. Reuses core's
// Finding/MoveFile and suibench's SubmittedFinding rather than re-declaring
// parallel shapes, so the result plugs straight into submitGrade. We don't
// validate severity against the Severity union (spec: non-empty string only).
import type { Finding, MoveFile, Severity } from "core";
import type { SubmittedFinding } from "suibench/submission";

export class ValidationError extends Error {}

export const MAX_FINDINGS = 50;
export const MAX_SCRIPT_BYTES = 256 * 1024;
export const MAX_REQUEST_BYTES = 5 * 1024 * 1024;

export type { SubmittedFinding };

export interface ParsedSubmission {
  datasetVersion: string;
  entryId: string;
  findings: SubmittedFinding[];
}

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ValidationError(`${label} must be a non-empty string`);
  }
  return value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new ValidationError(`${label} must be a string`);
  }
  return value;
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ValidationError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function parseFinding(raw: unknown, index: number): SubmittedFinding {
  const f = requireObject(raw, `findings[${index}]`);
  const finding = requireObject(f.finding, `findings[${index}].finding`);
  const script = requireObject(f.script, `findings[${index}].script`);

  const detail: Finding = {
    id: requireNonEmptyString(finding.id, `findings[${index}].finding.id`),
    module: requireNonEmptyString(finding.module, `findings[${index}].finding.module`),
    severity: requireNonEmptyString(finding.severity, `findings[${index}].finding.severity`) as Severity,
    title: requireNonEmptyString(finding.title, `findings[${index}].finding.title`),
    description: requireNonEmptyString(finding.description, `findings[${index}].finding.description`),
  };

  const path = requireNonEmptyString(script.path, `findings[${index}].script.path`);
  const contents = requireString(script.contents, `findings[${index}].script.contents`);
  if (Buffer.byteLength(contents, "utf-8") > MAX_SCRIPT_BYTES) {
    throw new ValidationError(`findings[${index}].script.contents exceeds ${MAX_SCRIPT_BYTES} bytes`);
  }

  return { finding: detail, script: { path, contents } };
}

export function parseSubmission(body: unknown): ParsedSubmission {
  const obj = requireObject(body, "body");

  const datasetVersion = requireNonEmptyString(obj.datasetVersion, "datasetVersion");
  const entryId = requireNonEmptyString(obj.entryId, "entryId");

  if (!Array.isArray(obj.findings)) {
    throw new ValidationError("findings must be an array");
  }
  if (obj.findings.length < 1 || obj.findings.length > MAX_FINDINGS) {
    throw new ValidationError(`findings must contain 1-${MAX_FINDINGS} entries`);
  }

  return {
    datasetVersion,
    entryId,
    findings: obj.findings.map((f, i) => parseFinding(f, i)),
  };
}
