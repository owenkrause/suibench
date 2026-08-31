import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["dataset/upgradecap_identity_unchecked/check.test.ts"] },
});
