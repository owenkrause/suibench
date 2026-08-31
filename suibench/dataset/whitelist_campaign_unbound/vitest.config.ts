import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["dataset/whitelist_campaign_unbound/check.test.ts"] },
});
