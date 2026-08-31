// Types for the perturbation / twin generator (design spec
// docs/superpowers/specs/2026-07-18-perturbation-testing-design.md).
//
// Kept in this dedicated module (NOT src/eval/types.ts) so the parallel pass@k
// branch — which extends src/eval/types.ts with `PerturbationResult` and the
// `perturbation` scorecard block — does not merge-collide with the twin core.
// The gap-scoring types (`PerturbationResult`) are deferred to that branch; this
// module owns only what the transformer + admissibility gate need.

/** A single old→new identifier rename. `kind` distinguishes module-position
 *  renames from member-position renames and drives the OTW witness constraint. */
export interface Rename {
  kind:
    | "package"
    | "module"
    | "function"
    | "type"
    | "field"
    | "constant"
    | "witness";
  from: string;
  to: string;
}

/**
 * The single rename manifest that drives BOTH the Move-source rewrite (AST) and
 * the TypeScript-harness rewrite (string substitution), so sources and harness
 * can never drift (design §2 decision (c), §3.2).
 *
 * `byModule` groups renames so a qualified `mod::sym` reference in another
 * source file resolves the tail against the right module. `moduleRenames` maps
 * old module name → new module name. `all` is the flat closure used by the
 * grep-based closure gate (§3.4 gate 5) and the harness string rewriter.
 */
export interface RenameManifest {
  /** Deterministic seed the manifest was derived from (`source_hash + index`). */
  seed: string;
  /** Our package address aliases (from `EntrySymbols.packages`); a qualified
   *  reference is only ours when its head is one of these — foreign heads freeze.
   *  Not renamed themselves (the on-chain alias stays consistent). */
  packages: string[];
  /** old module name → new module name. */
  moduleRenames: Record<string, string>;
  /** All renames, flat. `from` values are unique within module/member namespaces. */
  all: Rename[];
  /** Package name rename (Move.toml `name` + `challenge::` alias), if any.
   *  The corpus uses a fixed `challenge` package alias; renaming it is optional
   *  and off by default (the harness never names the package by literal — it
   *  uses the dynamic `packageId`), so this is usually undefined. */
  packageRename?: { from: string; to: string };
}

/** A file's path (relative to the entry dir) and its rewritten content. */
export interface TwinFile {
  /** Path relative to the entry directory, e.g. "sources/token.move". */
  relPath: string;
  content: string;
}

/** Output of the pure transformer: the rewritten files + the manifest used. */
export interface TwinResult {
  files: TwinFile[];
  manifest: RenameManifest;
}

/** Symbol set extracted from an entry's Move sources by the parser. */
export interface EntrySymbols {
  /** Package address aliases the entry DECLARES modules under (the head of
   *  `module <alias>::name` — usually `challenge`, sometimes `integer_mate`).
   *  A qualified `<alias>::mod::sym` reference is OURS (rename mod/sym); a
   *  foreign head (`sui`, `std`, a dependency) is NOT, even when its tail
   *  coincides with one of our module names (`use sui::math` vs our `math`). */
  packages: string[];
  /** Declared module short-names (e.g. "token"). */
  modules: string[];
  /** Declared struct/enum type names. */
  types: string[];
  /** Declared function names (public + private; the manifest renames all our
   *  own declarations — private ones are Class-B free renames). */
  functions: string[];
  /** Declared struct field names. */
  fields: string[];
  /** Declared constant names. */
  constants: string[];
  /** OTW witness struct names (module-name upper-cased, `has drop`, zero-field).
   *  Tracked separately so the manifest can honor the OTW naming constraint. */
  witnesses: string[];
}

/** The entry's files, keyed by entry-relative path (e.g. "sources/token.move",
 *  "exploits/admincap-leak.ts"), plus the parsed entry.json manifest. */
export interface EntryFiles {
  files: Record<string, string>;
  entry: import("../dataset/manifest.js").Manifest;
}
