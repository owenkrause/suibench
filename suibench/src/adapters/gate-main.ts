// Container entrypoint for the gate (node:slim). All config via env so the image
// is a pure forwarder with no baked topology. Started as its own container on
// attack-net + chain-net; the host drives drain over the control-plane UDS.
import { Gate } from "./gate.js";

const num = (k: string, d: number) => (process.env[k] ? Number(process.env[k]) : d);

const gate = new Gate({
  dataPort: num("DATA_PORT", 9000),
  bindHost: process.env.BIND_HOST ?? "0.0.0.0",
  controlPath: process.env.CONTROL_PATH ?? "/tmp/gate.sock",   // /tmp, not /run: the gate runs as non-root `node`, which can't bind in root-owned /run
  upstreamHost: process.env.UPSTREAM_HOST ?? "127.0.0.1",
  upstreamPort: num("UPSTREAM_PORT", 9000),
  drainDeadlineMs: num("DRAIN_DEADLINE_MS", 30_000),
  caps: {
    maxConcurrent: num("CAP_CONCURRENT", 512),
    maxTotalSubmits: num("CAP_TOTAL_SUBMITS", 10_000),
    ratePerSec: num("CAP_RATE", 1_000_000),
    maxRequestBytes: num("CAP_REQ_BYTES", 64 << 20),
    maxResponseBytes: num("CAP_RESP_BYTES", 64 << 20),
    maxConnections: num("CAP_CONNECTIONS", 1024),
  },
});

await gate.start();
console.log(`GATE_READY data=${gate.dataPort}`);
