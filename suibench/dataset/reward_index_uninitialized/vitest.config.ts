import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["dataset/reward_index_uninitialized/check.test.ts"] },
});
