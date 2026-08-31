import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["dataset/unsegregated_protocol_fee/check.test.ts"] },
});
