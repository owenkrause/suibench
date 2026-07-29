// The perturbation `transform_version` — a content hash over the engine's
// determining inputs (every non-test `.ts` in this dir + the tree-sitter-move
// grammar). Computed at RUNTIME, so nothing generated is committed into `src/`.
// The engine runs from `src/` via tsx (the gate, the tests, and the `--perturb`
// CLI all use `node --import tsx`), so `import.meta.dirname` is `src/perturbation`
// and the `.ts` sources are the canonical inputs. The self-containment test
// (version.test.ts) is what makes this hash COMPLETE: nothing here imports a
// value from outside the package, so hashing this dir + the wasm captures
// everything that can change a twin's bytes. It's called ~once per run (manifest
// assembly), and the hash is deterministic, so it is not memoized.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";

export function transformVersion(): string {
  const dir = import.meta.dirname;
  const h = createHash("sha256");
  for (const f of readdirSync(dir)
    .filter((n) => n.endsWith(".ts") && !n.endsWith(".test.ts"))
    .sort()) {
    h.update(readFileSync(join(dir, f)));
  }
  const require = createRequire(import.meta.url);
  h.update(
    readFileSync(require.resolve("@mysten/prettier-plugin-move/tree-sitter-move.wasm")),
  );
  return "perturb:" + h.digest("hex").slice(0, 12);
}
