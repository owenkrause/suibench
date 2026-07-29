// The transformer — the (near-)pure core that turns an entry's file set + a seed
// into a twin file set + the rename manifest.
//
// "Near-pure": file contents in, file contents out (no filesystem), but async
// because the Move parser (WASM) is async. All randomness flows through the
// seed, so `(files, seed) ⇒ twin` is deterministic and unit-testable with
// in-memory fixtures.
//
// What it rewrites, all from ONE manifest:
//   - sources/**.move        → Move AST rename + comment strip
//   - patches/<id>/**.move   → Move AST rename + comment strip (same as sources/)
//   - check.ts, functional.ts, exploits/**.ts, harness/setup.ts, harness/victim.ts
//                            → harness string rename + comment strip
//   - entry.json             → vulns[].module renamed; id/title/severity/
//                              root_cause/harm PRESERVED (attribution keys on id)
import {
  extractSymbols,
  collectAllLocalBindings,
  renameSource,
  stripMoveComments,
} from "./parser.js";
import { buildRenameManifest } from "./manifest.js";
import { renameHarness, stripTsComments } from "./harness.js";
import type { EntryFiles, RenameManifest, TwinFile, TwinResult } from "./types.js";
import type { Manifest } from "../dataset/manifest.js";

const MOVE_RE = /\.move$/;
const isSource = (p: string) => p.startsWith("sources/") && MOVE_RE.test(p);
const isPatchMove = (p: string) => p.startsWith("patches/") && MOVE_RE.test(p);
// suibench harness TS lives at the entry root (check.ts, functional.ts) + exploits/ + harness/setup|victim.
const isHarnessTs = (p: string) =>
  p === "check.ts" ||
  p === "functional.ts" ||
  (p.startsWith("exploits/") && p.endsWith(".ts")) ||
  p === "harness/setup.ts" ||
  p === "harness/victim.ts";

export async function generateTwin(
  entry: EntryFiles,
  seed: string,
): Promise<TwinResult> {
  const sourcePaths = Object.keys(entry.files).filter(isSource).sort();
  if (sourcePaths.length === 0)
    throw new Error("perturbation/transform: entry has no sources/*.move");

  const sources = sourcePaths.map((relPath) => ({
    relPath,
    content: entry.files[relPath],
  }));
  const symbols = await extractSymbols(sources);
  // Freeze shadow-ambiguous symbols (also bound as a local/param somewhere) so a
  // cross-module caller and the callee's declaration never drift apart.
  const localBindings = await collectAllLocalBindings(sources);
  const manifest = buildRenameManifest(symbols, seed, localBindings);

  const out: TwinFile[] = [];
  for (const [relPath, content] of Object.entries(entry.files)) {
    if (isSource(relPath) || isPatchMove(relPath)) {
      const renamed = await renameSource(relPath, content, manifest);
      out.push({ relPath, content: await stripMoveComments(renamed) });
    } else if (isHarnessTs(relPath)) {
      out.push({ relPath, content: stripTsComments(renameHarness(content, manifest)) });
    } else if (relPath === "entry.json") {
      // rewritten below from the parsed manifest
    } else if (relPath === "Move.toml") {
      out.push({ relPath, content }); // package alias unchanged (harness uses dynamic packageId)
    } else {
      // SOURCE.md etc. are not mounted/graded; drop from the twin dir.
    }
  }

  const rewritten = rewriteEntryJson(entry.entry, manifest);
  out.push({ relPath: "entry.json", content: JSON.stringify(rewritten, null, 2) + "\n" });
  out.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return { files: out, manifest };
}

/** Same strip as `generateTwin`, but with NO rename — comments only. Used to score
 *  the ORIGINAL entry on equal footing with its twin (twin comments are always
 *  stripped): without this, the original keeps comments as memorization anchors
 *  the twin lacks, confounding the perturbation gap with a comment-info gap
 *  instead of measuring rename robustness. No manifest is produced (nothing was
 *  renamed), so the returned manifest is a no-op placeholder. */
export async function stripEntry(entry: EntryFiles): Promise<TwinResult> {
  const out: TwinFile[] = [];
  for (const [relPath, content] of Object.entries(entry.files)) {
    if (isSource(relPath) || isPatchMove(relPath)) {
      out.push({ relPath, content: await stripMoveComments(content) });
    } else if (isHarnessTs(relPath)) {
      out.push({ relPath, content: stripTsComments(content) });
    } else if (relPath === "entry.json" || relPath === "Move.toml") {
      out.push({ relPath, content }); // unchanged
    } else {
      // SOURCE.md etc. are not mounted/graded; drop, matching generateTwin.
    }
  }
  out.sort((a, b) => a.relPath.localeCompare(b.relPath));
  const manifest: RenameManifest = { seed: "", packages: [], moduleRenames: {}, all: [] };
  return { files: out, manifest };
}

/** Rename `vulns[].module`; PRESERVE id/title/severity/root_cause/harm (attribution
 *  keys on `id`, which must stay stable). No `locations` in the suibench schema. */
export function rewriteEntryJson(m: Manifest, renames: RenameManifest): Manifest {
  return {
    ...m,
    vulns: m.vulns.map((v) => ({ ...v, module: renames.moduleRenames[v.module] ?? v.module })),
  };
}
