import { describe, expect, it } from "vitest";
import { classifyScrub } from "./image-scrub.js";

describe("classifyScrub", () => {
  it("flags dataset markers and harness modules", () => {
    const { forbidden } = classifyScrub([
      "/workspace/entrypoint.sh",                       // ok
      "/workspace/suibench/dataset/vault/check.ts",      // forbidden — dataset marker
      "/workspace/suibench/dist/adapters/confirmer.js",  // forbidden — harness
      "/workspace/suibench/dist/bench/driver.js",        // forbidden — harness
      "/workspace/entry.json",                           // forbidden — dataset marker
    ]);
    expect(forbidden).toEqual([
      "/workspace/suibench/dataset/vault/check.ts",
      "/workspace/suibench/dist/adapters/confirmer.js",
      "/workspace/suibench/dist/bench/driver.js",
      "/workspace/entry.json",
    ]);
  });
  it("does NOT flag a bare Move sources/ path", () => {
    // The .move framework cache legitimately ships Move `sources/`; a bare
    // sources/ path must never be treated as a violation.
    const { forbidden } = classifyScrub(["/workspace/some/sources/foo.move"]);
    expect(forbidden).toEqual([]);
  });

  it("flags first-party packages hidden in pnpm's virtual store", () => {
    const { forbidden } = classifyScrub([
      "/workspace/node_modules/core",
      "/workspace/node_modules/.pnpm/core@file+sui-sec+core/node_modules/core/dist/kernel/scorer.js",
      "/workspace/node_modules/.pnpm/suibench@file+sui-sec+suibench/node_modules/suibench/package.json",
      "/workspace/node_modules/.pnpm/suixploit@file+sui-sec+suixploit/node_modules/suixploit/dist/index.js",
      "/workspace/node_modules/.pnpm/@mysten+sui@2.22.0/node_modules/@mysten/sui/package.json",
    ]);

    expect(forbidden).toEqual([
      "/workspace/node_modules/core",
      "/workspace/node_modules/.pnpm/core@file+sui-sec+core/node_modules/core/dist/kernel/scorer.js",
      "/workspace/node_modules/.pnpm/suibench@file+sui-sec+suibench/node_modules/suibench/package.json",
      "/workspace/node_modules/.pnpm/suixploit@file+sui-sec+suixploit/node_modules/suixploit/dist/index.js",
    ]);
  });
});
