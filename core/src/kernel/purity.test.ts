// Integrity guard (principle 1): the kernel is pure. If any kernel file ever
// imports something effectful (a chain SDK, node builtins, an adapter), this
// fails — so the "kernel imports nothing effectful" invariant can't silently rot.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const KERNEL_DIR = dirname(fileURLToPath(import.meta.url));
const FORBIDDEN = /from\s+["'](@mysten\/|node:|.*\/adapters|.*\/runtime|.*docker)/;

describe("kernel purity", () => {
  const files = readdirSync(KERNEL_DIR).filter(
    (f) => f.endsWith(".ts") && !f.endsWith(".test.ts"),
  );

  for (const f of files) {
    it(`${f} imports nothing effectful`, () => {
      const src = readFileSync(join(KERNEL_DIR, f), "utf-8");
      const hit = src.split("\n").find((l) => FORBIDDEN.test(l));
      expect(hit, `forbidden import in ${f}: ${hit}`).toBeUndefined();
    });
  }
});
