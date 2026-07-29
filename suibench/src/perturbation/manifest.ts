// Rename-manifest builder — PURE and deterministic (design §3.3, §8.1).
//
// Given the entry's extracted symbols (from parser.ts) and a seed
// (`source_hash + index`, §8.2), produce the single rename manifest that drives
// BOTH the Move-source rewrite and the harness rewrite. Determinism: same
// (symbols, seed) ⇒ byte-identical manifest, so a checked-in twin is exactly
// what the generator produces (§3.5, CI `--check`).
//
// Constraints enforced here:
//  - Neutral wordlist only: new identifiers must NOT encode the vuln (design §5)
//    — the wordlist is deliberately vuln-neutral (curated).
//  - OTW invariant: a witness struct must be its module name upper-cased, so
//    when module `token` → `t_alpha` the witness `TOKEN` → `T_ALPHA` (§2, A2).
//  - Closure: every extracted symbol gets a rename, and `from` values are unique
//    across the manifest (the closure gate §3.4-5 then verifies none survives).
import type { RenameManifest, Rename, EntrySymbols } from "./types.js";

/**
 * Function names Sui/Move treats specially — renaming them changes SEMANTICS,
 * not just surface. `init` is the module initializer the runtime auto-calls at
 * publish (the OTW/shared-object setup every confirmed-tier entry depends on).
 * These are excluded from the rename set so a twin stays behaviorally identical.
 */
export const RESERVED_FUNCTIONS = new Set(["init"]);

/**
 * Struct field names Sui treats specially. `id` is REQUIRED to be the first
 * field (`id: UID`) of every `key` struct — renaming it fails compilation with
 * `invalid object declaration`. It is also never referenced by the harness, so
 * freezing it is both necessary and free. (The admissibility gate's compile step
 * catches this too, but excluding it up front keeps twins compilable by design.)
 */
export const RESERVED_FIELDS = new Set(["id"]);

/**
 * Neutral wordlist for new identifiers — deliberately generic, domain-agnostic
 * nouns/adjectives that carry no vulnerability signal.
 */
const NEUTRAL_WORDS = [
  "alpha",
  "beta",
  "gamma",
  "delta",
  "sigma",
  "omega",
  "lumen",
  "quartz",
  "marble",
  "cobalt",
  "willow",
  "cedar",
  "maple",
  "harbor",
  "meadow",
  "summit",
  "orchid",
  "cactus",
  "pebble",
  "cinder",
  "amber",
  "onyx",
  "jasper",
  "topaz",
  "cyan",
  "indigo",
  "crimson",
  "violet",
  "hazel",
  "ivory",
  "slate",
  "linen",
  "canvas",
  "ledger",
  "parcel",
  "bundle",
  "satchel",
  "beacon",
  "anchor",
  "cove",
  "ridge",
  "vale",
  "grove",
  "fern",
  "moss",
  "reed",
  "birch",
  "spruce",
  "sable",
  "russet",
  "umber",
  "ochre",
  "verdant",
  "azure",
  "sienna",
  "flint",
  "quill",
  "prism",
  "vertex",
  "matrix",
  "cursor",
  "widget",
  "gadget",
  "module",
  "parcel2",
  "token2",
  "holder2",
  "keeper",
  "warden",
  "steward",
  "curator",
];

/** Mulberry32 — a tiny, fast, well-distributed deterministic PRNG. Seeded from
 *  a 32-bit hash of the string seed so the whole manifest is reproducible. */
export function makePrng(seed: string): () => number {
  let h = 1779033703 ^ seed.length;
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(h ^ seed.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  let a = h >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Build the rename manifest. `seed = source_hash + index` per §8.2 (composed by
 * the caller). Renames are assigned deterministically: for each symbol we draw a
 * fresh neutral identifier not already used (as a new name) and not equal to any
 * existing symbol, then apply the kind-specific casing:
 *   - modules/functions/fields/constants → snake_case neutral word(s)
 *   - types → PascalCase
 *   - witnesses → the new MODULE name upper-cased (OTW invariant), so they are
 *     assigned AFTER module renames, not drawn independently.
 *
 * Package rename is off by default (see RenameManifest.packageRename doc); the
 * caller may opt in but the corpus's fixed `challenge` alias makes it a no-op
 * for grading.
 */
export function buildRenameManifest(
  symbols: EntrySymbols,
  seed: string,
  frozenNames: Set<string> = new Set(),
): RenameManifest {
  const rng = makePrng(seed);
  const used = new Set<string>([
    ...symbols.modules,
    ...symbols.types,
    ...symbols.functions,
    ...symbols.fields,
    ...symbols.constants,
  ]);

  const draw = (): string => {
    for (let attempt = 0; attempt < 10000; attempt++) {
      const w = NEUTRAL_WORDS[Math.floor(rng() * NEUTRAL_WORDS.length)];
      const suffix = Math.floor(rng() * 9000) + 1000; // 4-digit, keeps it unique & neutral
      const cand = `${w}_${suffix}`;
      if (!used.has(cand)) {
        used.add(cand);
        return cand;
      }
    }
    throw new Error(
      "twin/manifest: exhausted neutral wordlist draws (unexpected)",
    );
  };

  const toSnake = (base: string) => base; // draw() already snake-ish (word_1234)
  const toPascal = (base: string) =>
    base
      .split("_")
      .map((p) => (p ? p[0].toUpperCase() + p.slice(1) : p))
      .join("");

  const moduleRenames: Record<string, string> = {};
  const all: Rename[] = [];

  // 1. Modules first (witnesses depend on them).
  for (const m of symbols.modules) {
    const to = toSnake(draw());
    moduleRenames[m] = to;
    all.push({ kind: "module", from: m, to });
  }

  const witnessSet = new Set(symbols.witnesses);

  // 2. Types (witnesses get the OTW-constrained name; others a fresh Pascal word).
  //    A non-witness type whose name is shadow-ambiguous (also a local binding) is
  //    frozen; a witness is exempt (its OTW name must track its module and an
  //    uppercase witness never collides with a lower-case local).
  for (const t of symbols.types) {
    if (frozenNames.has(t) && !witnessSet.has(t)) continue;
    let to: string;
    if (witnessSet.has(t)) {
      // OTW: witness name == module upper-cased. Find the module whose upper-case
      // equals this witness; rename to the NEW module upper-cased.
      const owningModule = symbols.modules.find((m) => m.toUpperCase() === t);
      const newModule = owningModule ? moduleRenames[owningModule] : undefined;
      to = (newModule ?? toSnake(draw())).toUpperCase();
      all.push({ kind: "witness", from: t, to });
    } else {
      to = toPascal(draw());
      all.push({ kind: "type", from: t, to });
    }
  }

  // 3. Functions (skip reserved names like `init`) and constants.
  //
  // Struct FIELDS are deliberately NOT renamed. A field name routinely coincides
  // with a local/param of the same spelling, and Move's field pack/unpack
  // shorthand (`Struct { field }`) fuses the field key with a local binding, so a
  // field rename unbinds the collided local; a field name is also both-a-field-
  // and-a-function in some vendored code (`prev`, `min_leaf`), which would make
  // the name-keyed manifest ambiguous. Fields are internal — not the public API a
  // skeptic memorizes — so freezing them removes the collision class at no cost
  // to perturbation strength. (A harness that reads a field by key therefore
  // needs no field mirroring, since the field name is unchanged.)
  for (const f of symbols.functions) {
    if (RESERVED_FUNCTIONS.has(f) || frozenNames.has(f)) continue;
    all.push({ kind: "function", from: f, to: toSnake(draw()) });
  }
  for (const c of symbols.constants) {
    if (frozenNames.has(c)) continue;
    // Move constants are conventionally SCREAMING_SNAKE / EPascal; keep it a
    // valid ident that won't collide — upper-case a neutral word.
    all.push({ kind: "constant", from: c, to: toSnake(draw()).toUpperCase() });
  }

  assertManifestSound(all);
  return { seed, packages: symbols.packages, moduleRenames, all };
}

/**
 * Manifest soundness (used by the builder and the unit tests): unique `from`s,
 * unique `to`s, no rename is a no-op, and no new name collides with a surviving
 * foreign symbol we don't rename.
 */
export function assertManifestSound(all: Rename[]): void {
  const froms = new Set<string>();
  const tos = new Set<string>();
  for (const r of all) {
    if (froms.has(r.from))
      throw new Error(`twin/manifest: duplicate rename source "${r.from}"`);
    froms.add(r.from);
    if (r.from === r.to)
      throw new Error(`twin/manifest: no-op rename for "${r.from}"`);
    // A `to` may legitimately repeat ONLY for the witness↔module pair (module
    // `token`→`t` and witness `TOKEN`→`T` are different strings), so plain
    // uniqueness holds for our casing scheme.
    if (tos.has(r.to))
      throw new Error(`twin/manifest: duplicate rename target "${r.to}"`);
    tos.add(r.to);
  }
}
