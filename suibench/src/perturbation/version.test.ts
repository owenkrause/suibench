import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { transformVersion } from "./version.js";

describe("perturbation engine", () => {
  // The load-bearing invariant behind transform_version: the engine imports no
  // VALUE from outside `perturbation/`, so hashing this dir + the wasm is a
  // COMPLETE fingerprint. Only type-only cross-package references are allowed
  // (`import type ...` / an inline `import("../x").T` in a type position — both
  // erased at runtime, so they can't change a twin's bytes).
  it("is self-contained: no source under src/perturbation/ imports a value from outside the package", () => {
    const dir = import.meta.dirname;
    const offenders: string[] = [];
    for (const f of readdirSync(dir).filter(
      (n) => n.endsWith(".ts") && !n.endsWith(".test.ts"),
    )) {
      const src = readFileSync(join(dir, f), "utf-8");
      // A static `... from "../…"` is allowed only when the statement is a type
      // import/export. Scan back to the nearest `import`/`export` keyword (robust
      // to arbitrarily long named lists — no fixed-width lookback).
      for (const m of src.matchAll(/from\s+["'](\.\.[^"']*)["']/g)) {
        const kw = Math.max(
          src.lastIndexOf("import", m.index),
          src.lastIndexOf("export", m.index),
        );
        const clause = kw >= 0 ? src.slice(kw, m.index) : "";
        if (!/^(?:import|export)\s+type\b/.test(clause))
          offenders.push(`${f}: ${m[1]}`);
      }
      // A dynamic VALUE import of a `../…` specifier (awaited / assigned /
      // returned) escapes the package. A type-position `import("../x").T` is fine
      // (preceded by `:`/`typeof`, not by await/=/return), so it isn't matched.
      for (const m of src.matchAll(
        /(?:await|=|return)\s+import\s*\(\s*["'](\.\.[^"']*)["']/g,
      )) {
        offenders.push(`${f}: dynamic value import ${m[1]}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("transformVersion returns a stable content hash", () => {
    expect(transformVersion()).toMatch(/^perturb:[0-9a-f]{12}$/);
    expect(transformVersion()).toBe(transformVersion()); // deterministic, stable
  });
});
