import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Run only TypeScript sources under src/; `pnpm build` emits compiled *.test.js
    // copies into dist/ that would otherwise double the suite and run stale tests.
    include: ["src/**/*.test.ts"],
  },
});
