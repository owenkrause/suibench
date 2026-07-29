// Harness rewriter — manifest-driven STRING substitution (design §8.1(b), §3.2).
//
// The harness is TypeScript, not Move, so the parser does NOT touch it (§8.1):
// the single rename manifest (built from the Move AST symbol list) is applied to
// the harness by targeted string replacement. The harness references our symbols
// in exactly two literal shapes (design §2 "crux"):
//
//   1. Qualified move targets / type strings:  `${...}::<module>::<symbol>`
//      e.g. `${ctx.packageId}::token::mint`, `${ctx.packageId}::vault::AdminCap`.
//   2. (never a bare, unqualified reference — the harness always goes through a
//      `packageId::module::` prefix, verified across the corpus.)
//
// So the rewrite is: for every `::<oldModule>::` occurrence rename the module
// segment, and for every `::<oldModule>::<oldSymbol>` occurrence rename the
// trailing symbol segment too. We do this on the `::`-delimited path segments
// (word-boundary exact match), which cannot collide with unrelated TS
// identifiers because they are gated on the `::module::` qualified position.
//
// Patches and gold-patch .move files are NOT harness — they are full-file Move
// source replacements and are renamed by the Move AST renamer (parser.ts),
// exactly like sources/, so `applyPatch`'s basename/"must-exist" checks hold.
import type { RenameManifest } from "./types.js";

/**
 * Rewrite one harness TypeScript file. Renames occur ONLY inside qualified
 * `::seg::` paths, matching whole `::`-delimited segments — never a bare
 * substring — so a module named `token` never touches an unrelated `tokenize`.
 *
 * Algorithm: scan for the `::`-qualified path segments. A path segment is a
 * maximal run of `[A-Za-z0-9_]` immediately preceded by `::` OR immediately
 * followed by `::` while itself preceded by `::` or a template-expr close `}`.
 * We rename a segment iff it equals one of our module names (module position) or
 * one of our renamed symbols AND its preceding segment is one of our modules
 * (symbol position). This is the string mirror of the AST head/tail rule.
 */
export function renameHarness(
  content: string,
  manifest: RenameManifest,
): string {
  const moduleRenames = manifest.moduleRenames;
  const symbolRenames = new Map<string, string>();
  for (const r of manifest.all) {
    if (r.kind !== "module") symbolRenames.set(r.from, r.to);
  }

  // Match a `::seg1::seg2` or `::seg1` tail on a template/string path. We handle
  // the two shapes that appear: `<prefix>::MODULE::SYMBOL` and `<prefix>::MODULE`
  // (bare module, e.g. a type prefix). `<prefix>` ends in `}` (template expr) or
  // an identifier char (defensive). Replace only the MODULE and, when present,
  // the SYMBOL segment.
  const pathRe = /(::)([A-Za-z_][A-Za-z0-9_]*)(?:::([A-Za-z_][A-Za-z0-9_]*))?/g;

  return content.replace(
    pathRe,
    (whole: string, c1: string, mod: string, sym: string | undefined) => {
      const newMod = moduleRenames[mod];
      if (newMod === undefined) {
        // Not one of our modules in module-position → leave the whole path alone
        // (protects e.g. `sui::coin::mint`-style refs that never occur in harness,
        // and any incidental `::` in comments/strings).
        return whole;
      }
      if (sym !== undefined) {
        const newSym = symbolRenames.get(sym);
        const symOut = newSym ?? sym;
        return `${c1}${newMod}::${symOut}`;
      }
      return `${c1}${newMod}`;
    },
  );
}

/**
 * Strip ALL comments from a TypeScript harness file (design §8.5 symmetric
 * strip). Deterministic, no LLM. Handles `//` line comments and `/* … *​/` block
 * comments while ignoring `//`/`/*` that appear inside string / template
 * literals — a small hand-rolled tokenizer, since we don't want a TS parser dep
 * just for comment stripping and the harness files are simple.
 *
 * NOTE: harness comment-stripping is a decontamination nicety (the harness is
 * NEVER mounted to the hunter — sanitizeTarget excludes it), but stripping keeps
 * the checked-in twin clean and matches the "strip all comments" rule uniformly.
 */
export function stripTsComments(src: string): string {
  let out = "";
  let i = 0;
  const n = src.length;
  type Mode = "code" | "line" | "block" | "sq" | "dq" | "tpl";
  let mode: Mode = "code";
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (mode === "code") {
      if (c === "/" && c2 === "/") {
        mode = "line";
        i += 2;
        continue;
      }
      if (c === "/" && c2 === "*") {
        mode = "block";
        i += 2;
        continue;
      }
      if (c === "'") {
        mode = "sq";
        out += c;
        i++;
        continue;
      }
      if (c === '"') {
        mode = "dq";
        out += c;
        i++;
        continue;
      }
      if (c === "`") {
        mode = "tpl";
        out += c;
        i++;
        continue;
      }
      out += c;
      i++;
      continue;
    }
    if (mode === "line") {
      if (c === "\n") {
        mode = "code";
        out += c;
        i++;
        continue;
      }
      i++;
      continue;
    }
    if (mode === "block") {
      if (c === "*" && c2 === "/") {
        mode = "code";
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    // inside a string / template literal: copy verbatim, honoring escapes
    if (c === "\\") {
      out += c + (c2 ?? "");
      i += 2;
      continue;
    }
    if (mode === "sq" && c === "'") {
      mode = "code";
    } else if (mode === "dq" && c === '"') {
      mode = "code";
    } else if (mode === "tpl" && c === "`") {
      mode = "code";
    }
    out += c;
    i++;
  }
  return tidyTsBlankLines(out);
}

function tidyTsBlankLines(s: string): string {
  return s
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n");
}
