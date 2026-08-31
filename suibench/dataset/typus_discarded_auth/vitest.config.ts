import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["dataset/typus_discarded_auth/check.test.ts"] },
});
