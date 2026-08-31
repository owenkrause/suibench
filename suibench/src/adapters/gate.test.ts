import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer, request as httpRequest, type Server } from "node:http";
import { GrpcTypes } from "@mysten/sui/grpc";
import { EXEC_PATH, Gate, confirmVisible, type GateCaps, type DrainResult } from "./gate.js";

// Minimal gRPC-web DATA frame: [flags=0][len:4 BE][payload].
function dataFrame(payload: Buffer): Buffer {
  const h = Buffer.alloc(5);
  h.writeUInt32BE(payload.length, 1);
  return Buffer.concat([h, payload]);
}
// A trailers-only gRPC-web frame (flags 0x80) carrying a grpc-status.
function trailerFrame(status: number): Buffer {
  const t = Buffer.from(`grpc-status:${status}\r\n`, "ascii");
  const h = Buffer.alloc(5);
  h[0] = 0x80;
  h.writeUInt32BE(t.length, 1);
  return Buffer.concat([h, t]);
}
// A real successful unary response: a DATA frame followed by the terminal grpc-status:0 trailer.
function execResponse(digest: string): Buffer {
  const msg = dataFrame(Buffer.from(GrpcTypes.ExecuteTransactionResponse.toBinary(
    GrpcTypes.ExecuteTransactionResponse.create({ transaction: { digest } }),
  )));
  return Buffer.concat([msg, trailerFrame(0)]);
}
// A DATA frame with NO terminal trailer — an invalid unary response (the pinned client rejects it too).
function dataFrameOnly(digest: string): Buffer {
  return dataFrame(Buffer.from(GrpcTypes.ExecuteTransactionResponse.toBinary(
    GrpcTypes.ExecuteTransactionResponse.create({ transaction: { digest } }),
  )));
}
// A frame header that declares more bytes than it supplies — truncated framing.
function truncatedFrame(): Buffer {
  const h = Buffer.alloc(5);
  h.writeUInt32BE(100, 1);   // claims a 100-byte payload, supplies none
  return h;
}
function execRequest(paths?: string[]): Buffer {
  return dataFrame(Buffer.from(GrpcTypes.ExecuteTransactionRequest.toBinary(
    GrpcTypes.ExecuteTransactionRequest.create(paths ? { readMask: { paths } } : {}),
  )));
}

let upstream: Server;
let upstreamHits: string[];
let upstreamBodies: Buffer[];
let upstreamPort = 0;
let gate: Gate;
// Per-test override of the canned upstream response.
let upstreamResponder: () => { ct: string; body: Buffer; httpStatus?: number; delayMs?: number; broken?: boolean; headers?: Record<string, string> };

function makeOpts(caps: Partial<GateCaps> = {}, drainDeadlineMs = 3000, bindHost?: string) {
  return {
    dataPort: 0,
    controlPath: `/tmp/gate-test-${process.pid}.sock`,
    upstreamHost: "127.0.0.1",
    upstreamPort,
    caps: { maxConcurrent: 8, maxTotalSubmits: 100, ratePerSec: 1000, maxRequestBytes: 1 << 20, maxResponseBytes: 1 << 20, maxConnections: 64, ...caps },
    drainDeadlineMs,
    bindHost,
  };
}
// Restart the gate with overridden caps / drain deadline (a cap test tightens one cap).
async function startGate(caps?: Partial<GateCaps>, drainDeadlineMs?: number, bindHost?: string): Promise<void> {
  await gate.stop();
  gate = new Gate(makeOpts(caps, drainDeadlineMs, bindHost));
  await gate.start();
}

// A bodyless data-plane POST via node:http (undici's fetch surfaces spurious EPIPE when a *refused*
// request still has a body in flight — a harness artifact, not a gate behavior).
function postBare(port: number, path: string, ct: string): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": ct }, agent: false }, (r) => {
      const chunks: Buffer[] = [];
      r.on("data", (c) => chunks.push(c as Buffer));
      r.on("end", () => resolve({ status: r.statusCode ?? 0, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end();
  });
}

function drainOverUds(sockPath: string): Promise<DrainResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath: sockPath, method: "POST", path: "/drain", agent: false }, (r) => {
      const chunks: Buffer[] = [];
      r.on("data", (c) => chunks.push(c as Buffer));
      r.on("end", () => resolve(JSON.parse(Buffer.concat(chunks).toString()) as DrainResult));
    });
    req.on("error", reject);
    req.end();
  });
}

beforeEach(async () => {
  upstreamHits = [];
  upstreamBodies = [];
  upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: dataFrame(Buffer.from("ok")) });
  upstream = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      upstreamHits.push(req.url ?? "");
      upstreamBodies.push(Buffer.concat(chunks));
      const { ct, body, httpStatus, delayMs, broken, headers } = upstreamResponder();
      const respond = () => {
        res.writeHead(httpStatus ?? 200, { "content-type": ct, ...headers });
        if (broken) { res.write(body.subarray(0, Math.min(3, body.length))); res.destroy(); }  // partial then abort
        else res.end(body);
      };
      if (delayMs) setTimeout(respond, delayMs); else respond();
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  upstreamPort = (upstream.address() as { port: number }).port;
  gate = new Gate(makeOpts());
  await gate.start();
});
afterEach(async () => {
  await gate.stop();
  await new Promise<void>((r) => upstream.close(() => r()));
});

async function call(path: string, contentType: string, body?: Buffer): Promise<{ status: number; body: Buffer }> {
  const res = await fetch(`http://127.0.0.1:${gate.dataPort}${path}`, {
    method: "POST",
    headers: { "content-type": contentType },
    // fetch's BodyInit union doesn't match Buffer's ArrayBufferLike generic under this TS/@types-node combo.
    body: new Uint8Array(body ?? dataFrame(Buffer.from("req"))),
  });
  return { status: res.status, body: Buffer.from(await res.arrayBuffer()) };
}

describe("gate — forward + fail-closed", () => {
  it("forwards a unary read to the upstream", async () => {
    const r = await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/grpc-web+proto");
    expect(upstreamHits).toContain("/sui.rpc.v2.LedgerService/GetServiceInfo");
    expect(r.body.length).toBeGreaterThan(0);
  });
  it("rejects text format (grpc-status 3), never touching upstream", async () => {
    const r = await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/grpc-web-text");
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(3);
  });
  it("rejects streaming SubscriptionService (grpc-status 12)", async () => {
    const r = await call("/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", "application/grpc-web+proto");
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(12);
  });

  it("accepts bare application/grpc-web", async () => {
    const r = await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/grpc-web");
    expect(upstreamHits).toContain("/sui.rpc.v2.LedgerService/GetServiceInfo");
    expect(r.body.length).toBeGreaterThan(0);
  });
  it("accepts application/grpc-web+proto", async () => {
    const r = await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/grpc-web+proto");
    expect(upstreamHits).toContain("/sui.rpc.v2.LedgerService/GetServiceInfo");
    expect(r.body.length).toBeGreaterThan(0);
  });
  it("rejects bare application/grpc (grpc-status 3)", async () => {
    const r = await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/grpc");
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(3);
  });
  it("rejects application/json (grpc-status 3)", async () => {
    const r = await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/json");
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(3);
  });
  it("rejects application/grpc-web+json (grpc-status 3) — the allowlist closes this loosening", async () => {
    const r = await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/grpc-web+json");
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(3);
  });
});

describe("gate — submit handling", () => {
  it("rewrites the submit read_mask to include `digest` (preserving existing paths)", async () => {
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: execResponse("D1") });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest(["effects.status"]));
    // the fake upstream received the REWRITTEN request; decode its single data frame.
    const forwarded = GrpcTypes.ExecuteTransactionRequest.fromBinary(new Uint8Array(upstreamBodies[0].subarray(5)));
    expect(forwarded.readMask?.paths).toContain("digest");
    expect(forwarded.readMask?.paths).toContain("effects.status");
    expect(gate.peekSubmits()).toEqual([{ kind: "success", digest: "D1" }]);
    expect(gate.peekDigests()).toEqual(["D1"]);
  });

  it("adds `digest` to the default mask when the request has none", async () => {
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: execResponse("D2") });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    const forwarded = GrpcTypes.ExecuteTransactionRequest.fromBinary(new Uint8Array(upstreamBodies[0].subarray(5)));
    expect(forwarded.readMask?.paths).toEqual(expect.arrayContaining(["effects.status", "checkpoint", "digest"]));
  });

  it("classifies a nonzero-status submit response as ambiguous, not rejected", async () => {
    // grpc-status 4 (DEADLINE_EXCEEDED) — may have committed, so NOT proof of no-commit.
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: trailerFrame(4) });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    expect(gate.peekSubmits()).toEqual([{ kind: "ambiguous", reason: "status=4" }]);
    expect(gate.peekDigests()).toEqual([]);
  });

  it("marks a submit response with NO terminal trailer as ambiguous (not success)", async () => {
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: dataFrameOnly("D") });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    expect(gate.peekSubmits()).toEqual([{ kind: "ambiguous", reason: "no terminal grpc-status" }]);
  });

  it("does NOT accept a grpc-status HEADER beside a DATA frame with no trailer (ambiguous, not success)", async () => {
    // A unary response must carry its terminal status in a body trailer; a bare header next to a DATA
    // frame is an invalid framing the pinned client rejects — it must never be read as a committed success.
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: dataFrameOnly("D"), headers: { "grpc-status": "0" } });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    expect(gate.peekSubmits()).toEqual([{ kind: "ambiguous", reason: "no terminal grpc-status" }]);
    expect(gate.peekDigests()).toEqual([]);
  });

  it("honors a grpc-status header for a genuine trailers-only response (no DATA frame)", async () => {
    // Trailers-only: no DATA frame, status in the header — a valid gRPC-web error shape. Nonzero ⇒ ambiguous.
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: Buffer.alloc(0), headers: { "grpc-status": "5" } });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    expect(gate.peekSubmits()).toEqual([{ kind: "ambiguous", reason: "status=5" }]);
  });

  it("marks a header/trailer status disagreement as ambiguous", async () => {
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: execResponse("D"), headers: { "grpc-status": "5" } });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    expect(gate.peekSubmits()).toEqual([{ kind: "ambiguous", reason: "no terminal grpc-status" }]);
  });

  it("marks a non-2xx HTTP submit response as ambiguous", async () => {
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: execResponse("D"), httpStatus: 502 });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    expect(gate.peekSubmits()).toEqual([{ kind: "ambiguous", reason: "http=502" }]);
  });

  it("marks a malformed-framing submit response (two data frames) as ambiguous", async () => {
    upstreamResponder = () => ({ ct: "application/grpc-web+proto", body: Buffer.concat([dataFrameOnly("A"), dataFrameOnly("B"), trailerFrame(0)]) });
    await call(EXEC_PATH, "application/grpc-web+proto", execRequest());
    expect(gate.peekSubmits()[0].kind).toBe("ambiguous");
    expect(gate.peekDigests()).toEqual([]);
  });

  it("rejects a malformed (truncated) submit request pre-forward, never forwarding", async () => {
    const r = await call(EXEC_PATH, "application/grpc-web+proto", truncatedFrame());
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(3);
    expect(gate.peekRejected()).toBe(1);
    expect(gate.peekSubmits()).toEqual([]);   // rejected is a counter, not in submits
  });

  it("rejects a query-string submit (status 3), records rejected, never forwards", async () => {
    const r = await call(`${EXEC_PATH}?x=1`, "application/grpc-web+proto", execRequest());
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(3);
    expect(gate.peekRejected()).toBe(1);
    expect(gate.peekRejectReasons()).toContain("query");
  });

  it("does not track reads as submits", async () => {
    await call("/sui.rpc.v2.LedgerService/GetServiceInfo", "application/grpc-web+proto");
    expect(gate.peekSubmits()).toEqual([]);
  });
});

describe("gate — caps + byte limits", () => {
  const CT = "application/grpc-web+proto";

  it("a read holds the concurrency slot — a submit is rejected while the read is in-flight", async () => {
    await startGate({ maxConcurrent: 1 });
    upstreamResponder = () => ({ ct: CT, body: dataFrame(Buffer.from("ok")), delayMs: 200 });
    const readP = call("/sui.rpc.v2.LedgerService/GetServiceInfo", CT);   // occupies the slot (upstream delayed)
    await new Promise((r) => setTimeout(r, 40));                          // let the read reach upstream
    const submit = await call(EXEC_PATH, CT, execRequest());             // slot taken by the read → rejected
    expect(grpcStatusOf(submit.body)).toBe(8);
    expect(gate.peekCapsHit()).toContain("concurrent");
    await readP;                                                          // let the read complete
  });

  it("rejects over the total-submits cap (status 8, recorded rejected)", async () => {
    await startGate({ maxTotalSubmits: 1 });
    upstreamResponder = () => ({ ct: CT, body: execResponse("D") });
    await call(EXEC_PATH, CT, execRequest());                    // 1st: under cap
    const r = await call(EXEC_PATH, CT, execRequest());          // 2nd: over cap
    expect(grpcStatusOf(r.body)).toBe(8);
    expect(gate.peekCapsHit()).toContain("total");
    expect(gate.peekRejected()).toBe(1);
  });

  it("rejects an over-size request pre-forward (status 8), never forwarding", async () => {
    await startGate({ maxRequestBytes: 8 });
    const r = await call(EXEC_PATH, CT, Buffer.alloc(64));       // 64 bytes > 8
    expect(upstreamHits).toHaveLength(0);
    expect(grpcStatusOf(r.body)).toBe(8);
    expect(gate.peekCapsHit()).toContain("request-bytes");
  });

  it("marks an over-size response as ambiguous (capsHit response-bytes)", async () => {
    await startGate({ maxResponseBytes: 8 });
    upstreamResponder = () => ({ ct: CT, body: execResponse("D".repeat(200)) });  // response > 8 bytes
    await call(EXEC_PATH, CT, execRequest());
    expect(gate.peekSubmits()[0].kind).toBe("ambiguous");
    expect(gate.peekCapsHit()).toContain("response-bytes");
  });

  it("rejects over the rate cap (status 8)", async () => {
    await startGate({ ratePerSec: 1 });
    upstreamResponder = () => ({ ct: CT, body: execResponse("D") });
    await call(EXEC_PATH, CT, execRequest());                    // 1st in the 1s window
    const r = await call(EXEC_PATH, CT, execRequest());          // 2nd — over rate
    expect(grpcStatusOf(r.body)).toBe(8);
    expect(gate.peekCapsHit()).toContain("rate");
  });

  it("marks a broken upstream response (socket destroyed mid-body) as ambiguous", async () => {
    upstreamResponder = () => ({ ct: CT, body: execResponse("D"), broken: true });   // partial then abort
    await call(EXEC_PATH, CT, execRequest());
    expect(gate.peekSubmits()[0].kind).toBe("ambiguous");
  });
});

describe("gate — control plane + drain", () => {
  const CT = "application/grpc-web+proto";

  it("drain settles an in-flight submit → complete + its digest", async () => {
    upstreamResponder = () => ({ ct: CT, body: execResponse("DG"), delayMs: 120 });
    const inflight = call(EXEC_PATH, CT, execRequest());          // starts, not awaited
    await new Promise((r) => setTimeout(r, 30));                  // in-flight when drain snapshots
    const result = await drainOverUds(gate.opts.controlPath);
    expect(result.kind).toBe("complete");
    expect(result.digests).toContain("DG");
    expect(result.ambiguous).toBe(0);
    await inflight;
  });

  it("rejects arrivals after the drain flip (status 14, not forwarded)", async () => {
    await drainOverUds(gate.opts.controlPath);                    // accepting = false
    const late = await postBare(gate.dataPort, "/sui.rpc.v2.LedgerService/GetServiceInfo", CT);
    expect(upstreamHits).toHaveLength(0);                         // never forwarded upstream
    expect(grpcStatusOf(late.body)).toBe(14);
  });

  it("a transport-failed in-flight submit drains as ambiguous", async () => {
    upstreamResponder = () => ({ ct: CT, body: execResponse("X"), delayMs: 120, broken: true });
    const inflight = call(EXEC_PATH, CT, execRequest());
    await new Promise((r) => setTimeout(r, 30));
    const result = await drainOverUds(gate.opts.controlPath);
    expect(result.kind).toBe("ambiguous");
    expect(result.ambiguous).toBe(1);
    await inflight.catch(() => {});
  });

  it("ignores reads — drain returns without waiting on an in-flight read", async () => {
    upstreamResponder = () => ({ ct: CT, body: dataFrame(Buffer.from("ok")), delayMs: 300 });
    const readP = call("/sui.rpc.v2.LedgerService/GetServiceInfo", CT);
    await new Promise((r) => setTimeout(r, 30));
    const t0 = performance.now();
    const result = await drainOverUds(gate.opts.controlPath);
    expect(performance.now() - t0).toBeLessThan(150);            // did NOT wait ~300ms for the read
    expect(result.kind).toBe("complete");
    await readP;
  });

  it("times out (kind:timeout) if a submit doesn't settle within the drain deadline", async () => {
    await startGate({}, 50);                                     // short drain deadline
    upstreamResponder = () => ({ ct: CT, body: execResponse("Y"), delayMs: 200 });   // won't settle in 50ms
    const inflight = call(EXEC_PATH, CT, execRequest());
    await new Promise((r) => setTimeout(r, 20));
    const result = await drainOverUds(gate.opts.controlPath);
    expect(result.kind).toBe("timeout");
    await inflight.catch(() => {});
  });

  it("a submit whose client disconnects during the upstream wait does not get stuck", async () => {
    upstreamResponder = () => ({ ct: CT, body: execResponse("Z"), delayMs: 100 });
    const controller = new AbortController();
    const p = fetch(`http://127.0.0.1:${gate.dataPort}${EXEC_PATH}`, {
      method: "POST",
      headers: { "content-type": CT },
      body: new Uint8Array(execRequest()),
      signal: controller.signal,
    }).catch(() => {});
    await new Promise((r) => setTimeout(r, 30));   // in-flight, upstream still pending
    controller.abort();                            // client drops while the upstream request is pending
    await new Promise((r) => setTimeout(r, 130));  // upstream responds (~100ms); gate relays to a dead res
    const result = await drainOverUds(gate.opts.controlPath);
    expect(result.kind).toBe("complete");          // NOT stuck → not a spurious timeout
    expect(result.digests).toContain("Z");         // the recorded digest isn't orphaned
    await p;
  });
});

describe("gate — bindHost", () => {
  it("binds the data plane to the configured host, not the hardcoded default", async () => {
    await startGate(undefined, undefined, "0.0.0.0");
    expect(gate.peekDataHost()).toBe("0.0.0.0");   // distinguishes from the 127.0.0.1 default
  });
});

describe("gate — header-timeout sweep", () => {
  it("arms the connections sweep finer than the headers-timeout deadline", () => {
    // headersTimeout only fires on the periodic connections sweep; Node's default interval (30s) is
    // coarser than the 5s deadline, so the sweep interval must be set below it or the cap never fires.
    expect(gate.peekHeaderSweep()).toEqual({ headersTimeout: 5000, connectionsCheckingInterval: 1000 });
  });
});

describe("confirmVisible", () => {
  const fastClient = { core: { waitForTransaction: async () => ({}) } };

  it("confirms all digests → complete", async () => {
    const r = await confirmVisible(fastClient, ["a", "b"], { perDigestMs: 100, overallMs: 500 });
    expect(r.kind).toBe("complete");
    expect(r.confirmed.sort()).toEqual(["a", "b"]);
  });

  it("empty digests → complete (nothing to confirm)", async () => {
    const r = await confirmVisible(fastClient, [], { perDigestMs: 100, overallMs: 500 });
    expect(r.kind).toBe("complete");
    expect(r.confirmed).toEqual([]);
  });

  it("a digest that never indexes → timeout, bounded (doesn't hang), others still confirmed", async () => {
    const hangClient = {
      core: {
        waitForTransaction: ({ digest }: { digest: string }) =>
          digest === "slow" ? new Promise<unknown>(() => {}) : Promise.resolve({}),
      },
    };
    const r = await confirmVisible(hangClient, ["ok", "slow"], { perDigestMs: 40, overallMs: 300 });
    expect(r.kind).toBe("timeout");
    expect(r.confirmed).toEqual(["ok"]);
  });

  it("does not mutate the returned confirmed after an overall timeout (late wait)", async () => {
    // "late" resolves ~80ms — AFTER the 40ms overall timeout, BEFORE its 500ms per-digest bound.
    const lateClient = {
      core: {
        waitForTransaction: ({ digest }: { digest: string }) =>
          digest === "late" ? new Promise((res) => setTimeout(res, 80)) : Promise.resolve({}),
      },
    };
    const r = await confirmVisible(lateClient, ["late"], { perDigestMs: 500, overallMs: 40 });
    expect(r.kind).toBe("timeout");
    expect(r.confirmed).toEqual([]);
    await new Promise((res) => setTimeout(res, 120));   // let the late wait resolve
    expect(r.confirmed).toEqual([]);                    // STILL empty — no post-return mutation
  });
});

// Reads grpc-status from a trailers-only gRPC-web frame (flags bit 0x80).
function grpcStatusOf(body: Buffer): number {
  const text = body.subarray(5).toString("ascii");
  return Number(/grpc-status:(\d+)/.exec(text)?.[1] ?? "-1");
}
