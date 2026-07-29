// Move parser boundary for the twin generator.
//
// Parser decision (design §8.1): use the OFFICIAL Mysten Move grammar, shipped
// as a prebuilt `tree-sitter-move.wasm` inside `@mysten/prettier-plugin-move`,
// driven through `web-tree-sitter` (WASM — no native toolchain, no build step).
// It was verified to parse ALL 103 source files in contracts/evals/ with zero
// ERROR/MISSING nodes across BOTH editions in the corpus (legacy `struct` /
// `public(friend)` AND 2024 `public struct` / `mut` / `module x;` statement
// form) — the two-edition constraint the spec requires before adopting a parser.
//
// This module does two things:
//   1. `extractSymbols` — the authoritative per-entry symbol list (module,
//      struct/enum, function, field, constant, OTW-witness names), which the
//      rename manifest is built from.
//   2. `renameSource` — apply a rename manifest to one .move file by rewriting
//      only the AST identifier leaves that resolve to OUR declared symbols,
//      never a foreign-module reference (e.g. `coin::mint`'s `mint` is left
//      alone even when we also declare a `mint`). Byte-range edits are applied
//      right-to-left so offsets stay valid — no substring/keyword collisions.
//
// The parser instance is loaded once and memoized. It is async (WASM init), so
// the transformer core that needs it is async; the manifest builder and comment
// helpers that operate on an already-extracted symbol set stay pure/sync.
import { createRequire } from "node:module";
import type { RenameManifest, EntrySymbols } from "./types.js";

const require = createRequire(import.meta.url);

// web-tree-sitter 0.20.8's per-node getters (`node.hasError`, `node.child(i)`)
// are marshaling-sensitive and throw on a stale node handle. The TreeCursor
// exposes stable plain PROPERTIES (`nodeType`, `startIndex`, `nodeText`,
// `nodeIsNamed`, `nodeIsMissing`) and cheap navigation (`gotoFirstChild` /
// `gotoNextSibling` / `gotoParent`), so we drive the cursor ONCE to materialize
// a plain-object AST (`Node`) and do all extraction/rewrite over that. This is
// both robust and keeps the rest of the module free of the wasm binding.
interface TSCursor {
  nodeType: string;
  nodeText: string;
  startIndex: number;
  endIndex: number;
  nodeIsNamed: boolean;
  nodeIsMissing: boolean;
  gotoFirstChild(): boolean;
  gotoNextSibling(): boolean;
  gotoParent(): boolean;
}
interface TSTree {
  walk(): TSCursor;
}
interface TSParser {
  parse(src: string): TSTree;
  setLanguage(l: unknown): void;
}
interface ParserCtor {
  init(): Promise<void>;
  Language: { load(path: string): Promise<unknown> };
  new (): TSParser;
}

/** Plain-object AST node materialized from the cursor. */
export interface Node {
  type: string;
  text: string;
  startIndex: number;
  endIndex: number;
  named: boolean;
  missing: boolean;
  children: Node[];
}

let parserPromise: Promise<TSParser> | null = null;

/** Load (once) the Move parser with the bundled Mysten grammar wasm. */
export async function getMoveParser(): Promise<TSParser> {
  if (!parserPromise) {
    parserPromise = (async () => {
      const Parser = require("web-tree-sitter") as ParserCtor;
      await Parser.init();
      const wasmPath =
        require.resolve("@mysten/prettier-plugin-move/tree-sitter-move.wasm");
      const Move = await Parser.Language.load(wasmPath);
      const parser = new Parser();
      parser.setLanguage(Move);
      return parser;
    })();
  }
  return parserPromise;
}

/** Parse a source into a plain-object AST via the TreeCursor. */
async function parseToAst(source: string): Promise<Node> {
  const parser = await getMoveParser();
  const cursor = parser.parse(source).walk();
  const build = (): Node => {
    const node: Node = {
      type: cursor.nodeType,
      text: cursor.nodeText,
      startIndex: cursor.startIndex,
      endIndex: cursor.endIndex,
      named: cursor.nodeIsNamed,
      missing: cursor.nodeIsMissing,
      children: [],
    };
    if (cursor.gotoFirstChild()) {
      do {
        node.children.push(build());
      } while (cursor.gotoNextSibling());
      cursor.gotoParent();
    }
    return node;
  };
  return build();
}

function nodeHasError(root: Node): boolean {
  let bad = false;
  walk(root, (n) => {
    if (n.type === "ERROR" || n.missing) bad = true;
  });
  return bad;
}

/** Depth-first visit of every node. */
function walk(node: Node, fn: (n: Node) => void): void {
  fn(node);
  for (const c of node.children) walk(c, fn);
}

/** Depth-first visit carrying the ancestor chain (root-first, excluding `node`
 *  itself). Used by the renamer to classify a leaf by its syntactic position. */
function walkWithAncestors(
  node: Node,
  fn: (n: Node, ancestors: Node[]) => void,
  ancestors: Node[] = [],
): void {
  fn(node, ancestors);
  const next = [...ancestors, node];
  for (const c of node.children) walkWithAncestors(c, fn, next);
}

/** Names bound as locals/params anywhere in a source: parameters, `let`
 *  bindings, destructuring binds, lambda params. A bare reference whose name is
 *  bound as a local is a local read (or a shadow of a same-named module symbol),
 *  never a reference to one of our module-level declarations, so the renamer must
 *  freeze it — this is the guard that keeps `let amount = …` / a `pool` param
 *  from being rewritten when a field/function shares that spelling. */
function collectLocalBindings(root: Node): Set<string> {
  const locals = new Set<string>();
  walk(root, (n) => {
    if (n.type === "variable_identifier") locals.add(n.text);
  });
  return locals;
}

/** Union of local/param binding names across ALL of a package's sources. Fed to
 *  the manifest builder to freeze shadow-ambiguous symbols GLOBALLY, so a symbol
 *  that is a local in its defining module is not renamed at a cross-module call
 *  site either (which would leave the callee's frozen declaration unbound). */
export async function collectAllLocalBindings(
  sources: { relPath: string; content: string }[],
): Promise<Set<string>> {
  const all = new Set<string>();
  for (const src of sources) {
    const root = await parseToAst(src.content);
    for (const name of collectLocalBindings(root)) all.add(name);
  }
  return all;
}

const namedChildren = (n: Node) => n.children.filter((c) => c.named);

/**
 * Extract the entry's declared symbols from one parsed source. Declarations are
 * read from their defining node types (`struct_identifier`, `function_identifier`,
 * `field_identifier`, `constant`'s name, the module short-name); this is the set
 * the manifest renames. Foreign references (stdlib `coin`, `transfer`, …) are
 * never declarations here, so they never enter the set — the collision guard is
 * structural, not a denylist.
 */
export async function extractSymbols(
  sources: { relPath: string; content: string }[],
): Promise<EntrySymbols> {
  const packages = new Set<string>();
  const modules = new Set<string>();
  const types = new Set<string>();
  const functions = new Set<string>();
  const fields = new Set<string>();
  const constants = new Set<string>();
  const witnesses = new Set<string>();

  for (const src of sources) {
    const root = await parseToAst(src.content);
    if (nodeHasError(root)) {
      throw new Error(
        `twin/parser: ${src.relPath} did not parse cleanly (has ERROR/MISSING nodes)`,
      );
    }
    // Declaration-scoped extraction: descend ONLY through module declarations
    // and their bodies, so we never mistake an imported foreign module (`use
    // sui::coin`) or a qualified reference (`coin::Coin`) for one of OUR
    // declarations. A blind walk over `module_identity` would wrongly harvest
    // `coin`/`url` and then rename the stdlib — the bug this scoping prevents.
    for (const md of descendantsOfType(root, "module_definition")) {
      const identity = firstChildOfType(md, ["module_identity"]);
      if (identity) {
        const parts = namedChildrenOfType(identity, "module_identifier");
        if (parts.length >= 1) modules.add(parts[parts.length - 1].text);
        // `module <alias>::name` — the head is a package alias we own.
        if (parts.length >= 2) packages.add(parts[0].text);
      }
      const body = firstChildOfType(md, ["module_body"]);
      // Declarations are direct children of module_body (see grammar); read only
      // those, not nested references.
      for (const decl of body ? body.children : []) {
        switch (decl.type) {
          case "struct_definition":
          case "enum_definition": {
            const id = firstChildOfType(decl, [
              "struct_identifier",
              "enum_identifier",
            ]);
            if (id) {
              types.add(id.text);
              if (isOtwWitness(decl, id.text)) witnesses.add(id.text);
            }
            // field identifiers are declaration-site inside datatype_fields
            const df = firstChildOfType(decl, ["datatype_fields"]);
            if (df)
              for (const fid of descendantsOfType(df, "field_identifier"))
                fields.add(fid.text);
            break;
          }
          case "function_definition": {
            const id = firstChildOfType(decl, ["function_identifier"]);
            if (id) functions.add(id.text);
            break;
          }
          case "constant": {
            const id = firstChildOfType(decl, [
              "constant_identifier",
              "identifier",
            ]);
            if (id) constants.add(id.text);
            break;
          }
        }
      }
    }
  }

  return {
    packages: [...packages],
    modules: [...modules],
    types: [...types],
    functions: [...functions],
    fields: [...fields],
    constants: [...constants],
    witnesses: [...witnesses],
  };
}

/** An OTW witness struct: `has drop`, exactly zero fields, name == a module
 *  upper-cased. We approximate structurally (drop + no fields) here; the
 *  module-name match is enforced by the manifest's OTW constraint. */
function isOtwWitness(structDef: Node, name: string): boolean {
  if (name !== name.toUpperCase()) return false;
  const abilities = firstChildOfType(structDef, ["ability_decls"]);
  const hasDrop = abilities ? /\bdrop\b/.test(abilities.text) : false;
  const fields = firstChildOfType(structDef, ["datatype_fields"]);
  const noFields = fields
    ? descendantsOfType(fields, "field_identifier").length === 0
    : true;
  return hasDrop && noFields;
}

function namedChildrenOfType(node: Node, type: string): Node[] {
  return namedChildren(node).filter((c) => c.type === type);
}

function firstChildOfType(node: Node, types: string[]): Node | null {
  for (const c of node.children) if (types.includes(c.type)) return c;
  return null;
}

function descendantsOfType(node: Node, type: string): Node[] {
  const out: Node[] = [];
  walk(node, (n) => {
    if (n.type === type) out.push(n);
  });
  return out;
}

function firstDescendantOfType(node: Node, type: string): Node | null {
  return descendantsOfType(node, type)[0] ?? null;
}

/**
 * Module aliases a source imports from a FOREIGN package via a bare
 * `use <pkg>::<module>[ as <alias>]`. The in-scope name is the `as` alias if
 * present, else the imported module's short name; it is foreign iff the import's
 * package head is not one of ours. Used to stop a bare `math::pow` reference from
 * being rewritten as our module `math` when the file actually imported the
 * stdlib `sui::math` under that same name.
 */
function collectForeignModuleAliases(
  root: Node,
  ourPackages: Set<string>,
): Set<string> {
  const foreign = new Set<string>();
  for (const use of descendantsOfType(root, "use_module")) {
    const identity = firstChildOfType(use, ["module_identity"]);
    if (!identity) continue;
    const parts = namedChildrenOfType(identity, "module_identifier");
    if (parts.length < 2) continue;
    const pkg = parts[0].text;
    const importedModule = parts[parts.length - 1].text;
    // an `as <alias>` puts a trailing module_identifier directly under use_module
    const aliasNode = use.children.find(
      (c) => c.type === "module_identifier" && c !== identity,
    );
    const alias = aliasNode ? aliasNode.text : importedModule;
    if (!ourPackages.has(pkg)) foreign.add(alias);
  }
  return foreign;
}

interface Edit {
  start: number;
  end: number;
  text: string;
}

/**
 * Apply a rename manifest to one Move source, AST-driven. We rewrite an
 * identifier leaf iff it resolves to one of OUR declared symbols:
 *
 *  - The trailing/only `identifier` (or `*_identifier`) of a BARE `module_access`
 *    (single-part: a local, a same-module type/fn/const ref) → rename by name.
 *  - A QUALIFIED `module_access` / `module_identity` (`head::tail`): rename the
 *    `head` iff it is one of our modules, and rename the `tail` iff head is one
 *    of our modules (an intra-package `other_mod::Type` ref). A foreign head
 *    (e.g. `coin`) leaves BOTH parts alone — this is the collision guard that
 *    protects `coin::mint` when we also declare `mint`.
 *  - Declaration-site leaves (`struct_identifier`, `function_identifier`, the
 *    module short-name, constant name) → rename by name.
 *
 * Two positions are deliberately FROZEN, because a rename there would either
 * break compilation or carry no memorization signal:
 *  - Struct fields (`field_identifier`, and the field name in pack/unpack
 *    shorthand) are never renamed. A field name routinely coincides with a
 *    local/param of the same spelling (`funds: coin::into_balance(funds)`), and
 *    the shorthand `Struct { field }` fuses the field key with a local read —
 *    renaming one side unbinds the other. Fields are internal (not in the public
 *    API a skeptic memorizes; the harness that reads a field by key is mirrored
 *    separately), so freezing them removes the whole collision class at no cost
 *    to perturbation strength.
 *  - A bare reference whose name is bound as a LOCAL anywhere in the source is
 *    treated as a local read and frozen, so a `let prev = …` local is never
 *    rewritten just because a function `prev` exists. (A same-named module symbol
 *    is thus left un-renamed in that source; the closure gate tolerates a frozen
 *    shadow-ambiguous symbol — it is not a leaked API name a reader would latch
 *    onto, and the twin stays compilable.)
 *
 * All matched spans are collected then applied right-to-left, so no offset
 * bookkeeping is needed and there is zero risk of substring/keyword collision.
 */
export async function renameSource(
  relPath: string,
  content: string,
  manifest: RenameManifest,
): Promise<string> {
  const root = await parseToAst(content);
  if (nodeHasError(root)) {
    throw new Error(`twin/parser: ${relPath} did not parse cleanly for rename`);
  }

  // `byName` covers NON-module symbols only (types/functions/fields/constants/
  // witnesses). Module renames are applied EXCLUSIVELY in module-position via
  // `moduleRenames` in the qualified-path pass — never to a bare identifier,
  // because a bare `vault` is a LOCAL/param that merely shares the module's
  // name, not a module reference (a module ref is always qualified `mod::…`).
  const byName = new Map<string, string>();
  for (const r of manifest.all)
    if (r.kind !== "module") byName.set(r.from, r.to);
  const moduleRenames = manifest.moduleRenames;
  const ourPackages = new Set(manifest.packages);

  // Module aliases this file imports from a FOREIGN package (`use sui::math`
  // brings `math` into scope as the foreign `sui::math`). When a foreign import
  // shadows one of our module names, a bare `math::pow` reference means the
  // foreign module, so we must NOT rename that head even though `math` is also
  // one of our module names. Collect the foreign aliases up front.
  const foreignModuleAliases = collectForeignModuleAliases(root, ourPackages);

  const edits: Edit[] = [];
  const push = (n: Node) => {
    const to = byName.get(n.text);
    if (to && to !== n.text)
      edits.push({ start: n.startIndex, end: n.endIndex, text: to });
  };
  // Track which leaf nodes were handled via qualified-path logic so the generic
  // pass does not double-handle (or wrongly rename a foreign tail).
  const handled = new Set<number>();
  const renameHeadTail = (head: Node | null, tail: Node | null) => {
    if (!head) return;
    const headIsOurModule =
      Object.prototype.hasOwnProperty.call(moduleRenames, head.text) &&
      !foreignModuleAliases.has(head.text);
    if (headIsOurModule) {
      // `ourmod::sym` — rename module head AND (if ours) the trailing symbol.
      edits.push({
        start: head.startIndex,
        end: head.endIndex,
        text: moduleRenames[head.text],
      });
      handled.add(head.startIndex);
      if (tail) {
        push(tail);
        handled.add(tail.startIndex);
      }
    } else if (
      tail &&
      ourPackages.has(head.text) &&
      Object.prototype.hasOwnProperty.call(moduleRenames, tail.text)
    ) {
      // `<our-pkg-alias>::ourmod` — the module declaration `challenge::token` or a
      // `challenge::mod::sym` package-qualified ref. Head is one of OUR package
      // aliases (not renamed); rename the tail module. Freeze head. Requiring the
      // head be ours is the guard that stops `use sui::math` from being rewritten
      // when we also declare a module `math` (foreign `sui` head ⇒ tail frozen).
      edits.push({
        start: tail.startIndex,
        end: tail.endIndex,
        text: moduleRenames[tail.text],
      });
      handled.add(head.startIndex);
      handled.add(tail.startIndex);
    } else {
      // Foreign module: freeze BOTH parts (protects `coin::mint`).
      handled.add(head.startIndex);
      if (tail) handled.add(tail.startIndex);
    }
  };

  walk(root, (n) => {
    if (n.type === "module_access" || n.type === "module_identity") {
      const head = firstChildOfType(n, ["module_identifier"]);
      const colon = /::/.test(n.text) && head;
      if (colon) {
        // qualified: head :: tail  (tail is the last `identifier`/`module_identifier`)
        let tail: Node | null = null;
        for (let i = n.children.length - 1; i >= 0; i--) {
          const c = n.children[i];
          if (
            (c.type === "identifier" || c.type === "module_identifier") &&
            c !== head
          ) {
            tail = c;
            break;
          }
        }
        renameHeadTail(head, tail);
      }
    }
  });

  // Locals/params bound in this source. A bare reference to one of these names
  // is a local read (or a shadow) and must be frozen (see the doc comment).
  const localBindings = collectLocalBindings(root);

  // Declaration-site leaf types that ALWAYS rename (they define one of our
  // module-level symbols; never a local, never a field). `field_identifier` is
  // intentionally absent — fields are frozen.
  const DECL_LEAF_TYPES = new Set([
    "struct_identifier",
    "enum_identifier",
    "function_identifier",
    "module_identifier",
    "constant_identifier",
    "type_parameter_identifier",
  ]);

  // A `use_member` (`use challenge::asset::ASSET` / `use sui::coin::{Coin}`) is
  // renamed IFF its importing module is one of OURS: `use challenge::asset::Vault`
  // must rename `Vault` (our type, renamed in its defining module), but
  // `use sui::coin::{Coin}` must not. The importing module is the LAST
  // `module_identifier` of the sibling `module_identity`; it is "ours" when it is
  // a key of `moduleRenames`. `Self` is a keyword and is never a symbol we rename.
  const useMemberImportsOurModule = (ancestors: Node[]): boolean => {
    const useDecl = ancestors.find((a) => a.type === "use_declaration");
    if (!useDecl) return false;
    const identity = firstDescendantOfType(useDecl, "module_identity");
    if (!identity) return false;
    const mods = identity.children.filter((c) => c.type === "module_identifier");
    const importing = mods[mods.length - 1];
    return (
      !!importing &&
      Object.prototype.hasOwnProperty.call(moduleRenames, importing.text)
    );
  };

  walkWithAncestors(root, (n, ancestors) => {
    if (n.children.length > 0 || handled.has(n.startIndex)) return;

    if (DECL_LEAF_TYPES.has(n.type)) {
      // A declaration/type-param leaf. Rename it — UNLESS its name is also bound
      // as a local somewhere in this source. Such a "shadow-ambiguous" symbol
      // (e.g. a function `is_left_child` with a `let is_left_child = …` local) is
      // frozen at BOTH its declaration and its references, because we cannot
      // distinguish the reference positions from local reads without full scope
      // analysis; renaming the declaration alone would unbind the call sites. The
      // symbol is a vendored-library internal, not the public API a skeptic
      // memorizes, so freezing it costs little perturbation. Module names can
      // never be locals, so `module_identifier` is never frozen here.
      if (n.type !== "module_identifier" && localBindings.has(n.text)) return;
      // `type_parameter_identifier` never appears in `byName` (params aren't
      // manifest symbols), so push() is a no-op for it; harmless.
      push(n);
      return;
    }

    if (n.type !== "identifier") return; // field_identifier, variable_identifier, etc. frozen

    const inUseMember = ancestors.some((a) => a.type === "use_member");
    if (inUseMember) {
      // Import member: rename only when importing one of our modules; never rename
      // `Self`, and never freeze-then-leak an imported OUR type.
      if (n.text !== "Self" && useMemberImportsOurModule(ancestors)) push(n);
      return;
    }

    // A bare reference. If a local of this name is bound in the source, it is a
    // local read (or a shadow of a same-named symbol) — freeze it.
    if (localBindings.has(n.text)) return;
    push(n);
  });

  return applyEdits(content, edits);
}

/** Apply byte-range edits right-to-left (dedup by start; last-writer for the
 *  rare identical-span overlap, which cannot happen for our disjoint leaves). */
export function applyEdits(content: string, edits: Edit[]): string {
  const seen = new Set<number>();
  const sorted = edits
    .filter((e) => {
      if (seen.has(e.start)) return false;
      seen.add(e.start);
      return true;
    })
    .sort((a, b) => b.start - a.start);
  let out = content;
  for (const e of sorted)
    out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

/** Strip ALL comments from a Move source via the AST (line + block comments),
 *  design §8.5 / B5. Applied symmetrically to original and twin at scoring time;
 *  here it is used on the twin's sources + patches. Trailing whitespace left by
 *  a removed trailing comment is trimmed; fully-blank lines are collapsed. */
export async function stripMoveComments(content: string): Promise<string> {
  const root = await parseToAst(content);
  const edits: Edit[] = [];
  walk(root, (n) => {
    if (n.type === "line_comment" || n.type === "block_comment") {
      edits.push({ start: n.startIndex, end: n.endIndex, text: "" });
    }
  });
  const stripped = applyEdits(content, edits);
  return tidyBlankLines(stripped);
}

/** Collapse runs of blank lines (3+ → at most 2) and trim trailing spaces —
 *  cosmetic cleanup after comment removal, deterministic. */
export function tidyBlankLines(s: string): string {
  return s
    .split("\n")
    .map((line) => line.replace(/[ \t]+$/g, ""))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n");
}
