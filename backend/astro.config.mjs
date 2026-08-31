// @ts-check
import node from "@astrojs/node";
import { defineConfig } from "astro/config";

// Benchmark grading server — a Node standalone server that must run on a
// Docker-capable host (NOT serverless/Vercel: grading spawns Docker localnets).
// Serves /api/benchmark/* on demand.
//
// bodySizeLimit: the node adapter defaults to ~1GB, far above MAX_REQUEST_BYTES
// (5MiB, see server/validate.ts) which the submissions handler enforces; set a
// bit above it so an oversize body is rejected by the platform before buffering.
export default defineConfig({
  output: "server",
  adapter: node({ mode: "standalone", bodySizeLimit: 6 * 1024 * 1024 }),
});
