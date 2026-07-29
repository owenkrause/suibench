// The effectful `PatchGraderBoundary`. It grades the model's patched sources:
// `compile` builds them; `confirmExploit` re-runs one vuln's exploit on the
// patched build via the Confirmer + the entry's check (the dual of the
// exploitation grader); `runFunctional` runs the legit flow, which passes iff
// it does not abort. The boundary closes over the entry + patched mount, so the
// kernel `gradePatch` passes only the vuln id.
import { readFileSync, rmSync } from "node:fs";
import { basename } from "node:path";
import type { PatchGraderBoundary, Check, Mount, MoveFile } from "core";
import { materializeMount, buildPackage } from "./sandbox.js";
import type { SandboxManager } from "./sandbox.js";
import { Confirmer } from "./confirmer.js";
import type { DatasetEntry } from "../dataset/index.js";

const DEFAULT_IMAGE = process.env.SUIBENCH_IMAGE ?? "suibench-auditor";

export interface PatchGraderDeps {
  entry: DatasetEntry;
  /** The model's patch overlaid on the entry's sources. */
  patchedMount: Mount;
  /** The entry's check — decides whether an exploit STILL succeeds. */
  check: Check;
  manager: SandboxManager;
  image?: string;
}

const readScript = (path: string): MoveFile => ({
  path: basename(path),
  contents: readFileSync(path, "utf-8"),
});

export function makePatchGraderBoundary(
  deps: PatchGraderDeps,
): PatchGraderBoundary {
  const { entry, patchedMount, check, manager } = deps;
  const image = deps.image ?? DEFAULT_IMAGE;

  return {
    async compile() {
      const dir = materializeMount(patchedMount);
      try {
        const res = await buildPackage(dir, image);
        return res.ok
          ? { compiles: true }
          : { compiles: false, error: res.output.trim().slice(-800) };
      } finally {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          /* best-effort */
        }
      }
    },

    async confirmExploit(vulnId) {
      const exploitPath = entry.exploits[vulnId];
      if (!exploitPath)
        throw new Error(`${entry.target}: no exploit for vuln "${vulnId}"`);
      const confirmer = new Confirmer(manager, entry.harness, image);
      const { delta, params } = await confirmer.runOnMount(
        patchedMount,
        readScript(exploitPath),
      );
      return { confirmed: check(delta, params) };
    },

    async runFunctional() {
      if (!entry.functionalPath)
        return { passed: false, error: `${entry.target}: no functional.ts` };
      const confirmer = new Confirmer(manager, entry.harness, image);
      return confirmer.runFunctional(
        patchedMount,
        readScript(entry.functionalPath),
      );
    },
  };
}
