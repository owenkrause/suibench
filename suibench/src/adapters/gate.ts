import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { unlinkSync } from "node:fs";
import { GrpcTypes } from "@mysten/sui/grpc";

export interface GateCaps {
  maxConcurrent: number;      // all active requests (reads + submits)
  maxTotalSubmits: number;
  ratePerSec: number;
  maxRequestBytes: number;    // memory bound — an unbounded body OOMs the gate before any timer fires
  maxResponseBytes: number;
  maxConnections: number;     // ceiling on concurrent TCP sockets — bounds pre-request (slowloris) storms
}
export interface GateOptions {
  dataPort: number; controlPath: string;
  upstreamHost: string; upstreamPort: number;
  caps: GateCaps; drainDeadlineMs: number;   // the one overall bound on settling in-flight submits (§7.3)
  bindHost?: string;   // data-plane bind address; default 127.0.0.1 (sidecar/tests), 0.0.0.0 in the gate container
}
export interface DrainResult {
  kind: "complete" | "ambiguous" | "timeout";   // ambiguous|timeout ⇒ confirmer InfraError (commit unknown)
  digests: string[];                             // from success outcomes
  rejected: number;
  ambiguous: number;
  capsHit: string[];
}

// A submit's terminal outcome for a FORWARDED request (spec §5.1/§7.3). success = HTTP 2xx + terminal
// grpc-status 0 + digest; ambiguous = any post-forward murk (nonzero status, transport failure, malformed
// framing, ok-without-digest) — commit unknown. Pre-forward refusals are counted separately (rejectedCount).
export type SubmitOutcome =
  | { kind: "success"; digest: string }
  | { kind: "ambiguous"; reason: string };

export const EXEC_PATH = "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction";
const STREAM_PREFIX = "/sui.rpc.v2.SubscriptionService/";
const READ_PREFIXES = ["/sui.rpc.v2.", "/sui.rpc.v2alpha."];
// Strict allowlist, not a prefix match — "+json"/"-text"/bare "grpc" must all reject.
const ALLOWED_CONTENT_TYPES = new Set(["application/grpc-web", "application/grpc-web+proto"]);

type Kind = "submit" | "read" | "reject";
function classify(path: string): Kind {
  if (path === EXEC_PATH) return "submit";
  if (path.startsWith(STREAM_PREFIX)) return "reject";          // streaming: never terminates
  if (READ_PREFIXES.some((p) => path.startsWith(p))) return "read";
  return "reject";
}

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// A socket that never completes its HTTP headers never fires a `request` (never enters the concurrency
// cap), so slowloris-style holds must be swept below the request layer. This deadline (Node's default is
// 60s) shrinks the hold window; caps.maxConnections caps the count. The primary control is container
// nofile/memory/pids limits — a storm is confined to the phase's own cgroup (spec §7.3).
const HEADERS_TIMEOUT_MS = 5_000;

// A trailers-only gRPC-web frame (flags bit 0x80) carrying a status — how the gate says "no".
function grpcWebStatus(res: ServerResponse, code: number, message = ""): void {
  const trailer = Buffer.from(`grpc-status:${code}\r\ngrpc-message:${message}\r\n`, "ascii");
  const header = Buffer.alloc(5);
  header[0] = 0x80;
  header.writeUInt32BE(trailer.length, 1);
  res.writeHead(200, { "content-type": "application/grpc-web+proto" });
  res.end(Buffer.concat([header, trailer]));
}

// Refuse a request: drain-and-discard any remaining request body, then send the gRPC error ONCE the body
// has fully arrived. Responding before the client finishes sending makes Node reset the socket (EPIPE on
// the client's in-flight write); draining first (flowing mode, no data listener ⇒ discarded, bounded
// memory) lets the send complete so the connection closes cleanly with the client getting the status.
function refuseStream(req: IncomingMessage, res: ServerResponse, code: number, message: string): void {
  req.on("error", () => {});
  // Respond and close PROMPTLY — do NOT drain an untrusted body (a slow/infinite refused body would
  // otherwise hold an off-budget socket open). Destroying after the error frame flushes closes the socket;
  // a client mid-send gets a reset, which for a refused request is fine.
  const close = () => req.destroy();
  res.once("finish", close);
  res.once("close", close);
  grpcWebStatus(res, code, message);
}

// A gRPC-web DATA frame: flags 0x00 + 4-byte BE length + payload.
function dataFrame(payload: Buffer): Buffer {
  const header = Buffer.alloc(5);
  header.writeUInt32BE(payload.length, 1);
  return Buffer.concat([header, payload]);
}

// Strictly parse a unary gRPC-web message: a sequence of length-prefixed frames, each flags byte
// exactly 0x00 (DATA) or 0x80 (TRAILER) — compression (0x01) and unknown bits are rejected — with a
// declared length that fits the buffer. A unary message has EXACTLY one DATA frame and at most one
// TRAILER; a second data frame, truncation, or a bad flag throws (the pinned client is this strict too).
function parseUnary(body: Buffer): { message: Buffer | null; trailer: Buffer | null } {
  let message: Buffer | null = null;
  let trailer: Buffer | null = null;
  let off = 0;
  while (off < body.length) {
    if (off + 5 > body.length) throw new Error("truncated frame header");
    const flags = body[off];
    const end = off + 5 + body.readUInt32BE(off + 1);
    if (end > body.length) throw new Error("truncated frame body");
    const payload = body.subarray(off + 5, end);
    if (flags === 0x00) {
      if (message !== null) throw new Error("multiple data frames");
      message = payload;
    } else if (flags === 0x80) {
      if (trailer !== null) throw new Error("multiple trailer frames");
      trailer = payload;
    } else {
      throw new Error(`unsupported frame flags 0x${flags.toString(16)}`);
    }
    off = end;
  }
  return { message, trailer };
}

// Union `digest` (ExecutedTransaction field 1 — what response.transaction.digest reads; NOT
// `transaction.digest`, the inner Transaction's) into the request read_mask: the default
// (`effects.status,checkpoint`) omits it, and the caller controls the mask. Throws on a malformed request.
function ensureDigestInReadMask(reqBody: Buffer): Buffer {
  const { message } = parseUnary(reqBody);
  if (!message) throw new Error("no request message");
  const req = GrpcTypes.ExecuteTransactionRequest.fromBinary(new Uint8Array(message));
  const paths = req.readMask?.paths ?? ["effects.status", "checkpoint"];
  if (!paths.includes("digest")) paths.push("digest");
  req.readMask = { paths };
  return dataFrame(Buffer.from(GrpcTypes.ExecuteTransactionRequest.toBinary(req)));
}

function extractDigest(message: Buffer): string | undefined {
  try {
    return GrpcTypes.ExecuteTransactionResponse.fromBinary(new Uint8Array(message)).transaction?.digest;
  } catch {
    return undefined;   // unparseable message ⇒ no digest ⇒ ambiguous (never crash the gate)
  }
}

// Terminal grpc-status for a unary response. The body TRAILER frame is authoritative; a bare `grpc-status`
// header is honored ONLY for a genuine trailers-only response (no DATA frame). A DATA frame with no
// terminal trailer is an invalid unary response (the pinned client rejects it too) ⇒ null; null too when
// the two sources disagree.
function terminalGrpcStatus(
  headers: Record<string, string>,
  frames: { message: Buffer | null; trailer: Buffer | null },
): number | null {
  const m = frames.trailer ? /grpc-status:\s*(\d+)/.exec(frames.trailer.toString("ascii")) : null;
  const trailerStatus = m ? Number(m[1]) : null;
  const header = headers["grpc-status"] !== undefined ? Number(headers["grpc-status"]) : null;
  if (trailerStatus !== null) {
    if (header !== null && header !== trailerStatus) return null;   // disagreement ⇒ ambiguous
    return trailerStatus;                                           // body trailer wins
  }
  return frames.message ? null : header;   // no trailer: valid only if trailers-only (no DATA frame)
}

// Called only on a completed forwarded response. success ONLY on HTTP 2xx + a strictly-framed body +
// a valid terminal grpc-status 0 + a digest; anything murky — non-2xx HTTP, malformed framing,
// missing/contradictory terminal status, nonzero status, or OK-without-digest — is ambiguous.
function classifySubmit(resp: { status: number; headers: Record<string, string>; body: Buffer }): SubmitOutcome {
  if (resp.status < 200 || resp.status >= 300) return { kind: "ambiguous", reason: `http=${resp.status}` };
  let frames: { message: Buffer | null; trailer: Buffer | null };
  try {
    frames = parseUnary(resp.body);
  } catch (err) {
    return { kind: "ambiguous", reason: `malformed response: ${errMsg(err)}` };
  }
  const status = terminalGrpcStatus(resp.headers, frames);
  if (status === null) return { kind: "ambiguous", reason: "no terminal grpc-status" };
  if (status !== 0) return { kind: "ambiguous", reason: `status=${status}` };
  const digest = frames.message ? extractDigest(frames.message) : undefined;
  return digest ? { kind: "success", digest } : { kind: "ambiguous", reason: "ok-without-digest" };
}

// A request or response body exceeded its byte cap (memory bound). `which` becomes the capsHit flag.
class ByteCapExceeded extends Error {
  constructor(readonly which: string) { super(`byte cap exceeded: ${which}`); }
}

// Buffer the request body, rejecting IMMEDIATELY the moment the cap is crossed (paused, not drained) —
// a slow oversized request must not hold a slot to EOF. The caller `refuseStream`s, which closes it.
function readBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const onData = (c: Buffer) => {
      total += c.length;
      // Remove ourselves (not pause) so the caller's refuseStream can drain the rest of an oversized body.
      if (total > maxBytes) { req.off("data", onData); reject(new ByteCapExceeded("request-bytes")); return; }
      chunks.push(c);
    };
    req.on("data", onData);
    req.once("end", () => resolve(Buffer.concat(chunks)));
    req.once("error", reject);
  });
}

// Only the headers the upstream gRPC-web server needs; drop hop-by-hop + host.
function forwardHeaders(h: IncomingMessage["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ["content-type", "te", "grpc-timeout", "x-grpc-web", "x-user-agent", "accept"]) {
    const v = h[k];
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

export class Gate {
  readonly opts: GateOptions;
  private data?: Server;
  private control?: Server;
  dataPort = 0;
  protected accepting = true;
  protected readonly active = new Set<Promise<void>>();          // all in-flight requests (concurrency cap)
  protected readonly inFlightSubmits = new Set<Promise<void>>(); // submit subset — drain awaits these (Task 4)
  protected readonly submits: SubmitOutcome[] = [];              // success | ambiguous (bounded by maxTotalSubmits)
  protected readonly capsHit = new Set<string>();
  private submitCount = 0;
  private rateWindow: number[] = [];                             // ms timestamps within the last second
  // Pre-forward refusals are aggregate (unbounded input, bounded memory): a count + a deduped reason set.
  protected rejectedCount = 0;
  protected readonly rejectReasons = new Set<string>();
  private draining?: Promise<DrainResult>;   // memoized so repeated /drain returns one idempotent boundary

  constructor(opts: GateOptions) { this.opts = opts; }

  async start(): Promise<void> {
    // Data plane: the phase's only endpoint (in production, on attack-net).
    // headersTimeout is only evaluated on the connections sweep; Node's default interval (30s) is
    // coarser than the 5s deadline, so sweep more often or the slow-header cap never actually fires.
    // (connectionsCheckingInterval has no typed Server-instance setter, only a constructor option.)
    this.data = createServer({ connectionsCheckingInterval: 1_000 }, (req, res) => this.handle(req, res));
    this.data.maxConnections = this.opts.caps.maxConnections;   // ceiling on concurrent sockets
    this.data.headersTimeout = HEADERS_TIMEOUT_MS;              // sweep sockets that never finish headers
    await new Promise<void>((r) => this.data!.listen(this.opts.dataPort, this.opts.bindHost ?? "127.0.0.1", r));
    this.dataPort = (this.data!.address() as { port: number }).port;
    // Control plane: a Unix-domain socket, unreachable from either network — the host drives drain over it
    // (in production via `docker exec <gate>`). A namespace boundary, not a password (spec §6.1).
    this.control = createServer((req, res) => this.handleControl(req, res));
    try { unlinkSync(this.opts.controlPath); } catch { /* no stale socket */ }
    await new Promise<void>((r) => this.control!.listen({ path: this.opts.controlPath }, r));
  }
  async stop(): Promise<void> {
    // Force-close live sockets first: server.close() waits for connections to end, and drain deliberately
    // leaves reads in flight, so a plain close() could hang the in-process lifecycle. (Prod uses docker rm -f.)
    this.data?.closeAllConnections();
    this.control?.closeAllConnections();
    if (this.data) await new Promise<void>((r) => this.data!.close(() => r()));
    if (this.control) await new Promise<void>((r) => this.control!.close(() => r()));
    try { unlinkSync(this.opts.controlPath); } catch { /* already gone */ }
  }

  private handleControl(req: IncomingMessage, res: ServerResponse): void {
    if (req.method === "POST" && req.url === "/drain") {
      void this.drain().then((r) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(r));
      });
      return;
    }
    res.writeHead(404);
    res.end();
  }

  // The boundary is realized here: stop admission, settle in-flight SUBMITS to terminal (bounded by ONE
  // overall drain deadline), and report. Reads are ignored — not awaited, not cancelled (the confirmer
  // removes the gate container right after drain, §5.1/§6.2, which reaps them). `kind=complete` only when
  // every submit settled with zero ambiguous; ambiguous/timeout ⇒ the confirmer InfraErrors the variant.
  // Idempotent: repeated /drain returns the same in-flight boundary (one deadline, one result).
  async drain(): Promise<DrainResult> {
    return (this.draining ??= this.runDrain());
  }

  private async runDrain(): Promise<DrainResult> {
    this.accepting = false;                                    // atomic flip; subsequent arrivals → 14
    const pending = [...this.inFlightSubmits];
    let timer: ReturnType<typeof setTimeout>;
    const settled = Promise.allSettled(pending).then(() => true);
    const timedOut = new Promise<false>((r) => { timer = setTimeout(() => r(false), this.opts.drainDeadlineMs); });
    const complete = await Promise.race([settled, timedOut]);
    clearTimeout(timer!);
    const digests = this.submits.flatMap((s) => (s.kind === "success" ? [s.digest] : []));
    const ambiguous = this.submits.filter((s) => s.kind === "ambiguous").length;
    return {
      kind: !complete ? "timeout" : ambiguous > 0 ? "ambiguous" : "complete",
      digests,
      rejected: this.rejectedCount,
      ambiguous,
      capsHit: [...this.capsHit],
    };
  }

  // Test-only accessors; the real read path is drain() (Task 4).
  peekSubmits(): SubmitOutcome[] { return [...this.submits]; }
  peekDigests(): string[] { return this.submits.flatMap((s) => (s.kind === "success" ? [s.digest] : [])); }
  peekCapsHit(): string[] { return [...this.capsHit]; }
  peekRejected(): number { return this.rejectedCount; }
  peekRejectReasons(): string[] { return [...this.rejectReasons]; }
  peekDataHost(): string { return (this.data!.address() as import("node:net").AddressInfo).address; }
  // connectionsCheckingInterval is a real Server instance property at runtime (set from the
  // constructor option), but @types/node only declares it on ServerOptions — hence the cast.
  peekHeaderSweep(): { headersTimeout: number; connectionsCheckingInterval: number } {
    const sweep = (this.data as unknown as { connectionsCheckingInterval: number }).connectionsCheckingInterval;
    return { headersTimeout: this.data!.headersTimeout, connectionsCheckingInterval: sweep };
  }

  private recordRejected(reason: string): void { this.rejectedCount++; this.rejectReasons.add(reason); }

  // Enforced BEFORE forwarding; the check + increments are synchronous, so no race with concurrent handlers.
  private capHit(kind: Kind, nowMs: number): string | null {
    if (this.active.size >= this.opts.caps.maxConcurrent) return "concurrent";
    this.rateWindow = this.rateWindow.filter((t) => nowMs - t < 1000);
    if (this.rateWindow.length >= this.opts.caps.ratePerSec) return "rate";
    if (kind === "submit" && this.submitCount >= this.opts.caps.maxTotalSubmits) return "total";
    return null;
  }

  protected handle(req: IncomingMessage, res: ServerResponse): void {
    // A client that resets/EPIPEs mid-exchange must never crash the gate (it serves untrusted input).
    req.on("error", () => {});
    res.on("error", () => {});
    if (!this.accepting) return refuseStream(req, res, 14, "drained");   // UNAVAILABLE
    const path = req.url ?? "";
    const ct = String(req.headers["content-type"] ?? "");
    if (!ALLOWED_CONTENT_TYPES.has(ct.split(";")[0].trim()))
      return this.refuse(req, res, path, 3, "format");                    // INVALID_ARGUMENT
    // Reject query strings: the localnet ignores the query and executes anyway (verified),
    // so a query-appended submit would otherwise slip classification into "read".
    if (path.includes("?")) return this.refuse(req, res, path, 3, "query");
    const kind = classify(path);
    if (kind === "reject") return this.refuse(req, res, path, 12, "unsupported"); // UNIMPLEMENTED
    const hit = this.capHit(kind, performance.now());
    if (hit) {                                                            // over a cap ⇒ pre-forward refusal
      this.capsHit.add(hit);
      if (kind === "submit") this.recordRejected(hit);
      return refuseStream(req, res, 8, hit);                             // RESOURCE_EXHAUSTED
    }
    this.rateWindow.push(performance.now());
    if (kind === "submit") this.submitCount++;
    const p = this.proxy(req, res, path, kind).catch(() => {
      if (!res.headersSent) grpcWebStatus(res, 13, "internal");          // defensive: proxy handles its own error paths
    });
    this.active.add(p);
    if (kind === "submit") this.inFlightSubmits.add(p);
    void p.finally(() => {
      this.active.delete(p);                                             // released only after proxy resolves — i.e. after the response flushes
      this.inFlightSubmits.delete(p);
    });
  }

  // A pre-forward refusal: count a rejected SUBMIT (definite non-commit) if the base path is a submit, then close.
  private refuse(req: IncomingMessage, res: ServerResponse, path: string, code: number, reason: string): void {
    if (classify(path.split("?")[0]) === "submit") this.recordRejected(reason);
    refuseStream(req, res, code, reason);
  }

  protected async proxy(req: IncomingMessage, res: ServerResponse, path: string, kind: Kind): Promise<void> {
    let body: Buffer;
    try {
      body = await readBody(req, this.opts.caps.maxRequestBytes);
    } catch (err) {
      if (err instanceof ByteCapExceeded) {                             // request too large — pre-forward
        this.capsHit.add(err.which);
        if (kind === "submit") this.recordRejected(err.which);
        if (!res.headersSent) refuseStream(req, res, 8, err.which);
        return;
      }
      if (kind === "submit") this.recordRejected(`incomplete: ${errMsg(err)}`);
      if (!res.headersSent) refuseStream(req, res, 3, "incomplete");     // incomplete request — pre-forward
      return;
    }
    let forwardBody = body;
    if (kind === "submit") {
      try {
        forwardBody = ensureDigestInReadMask(body);                     // union `digest` into read_mask
      } catch (err) {                                                   // malformed request — pre-forward
        this.recordRejected(`malformed: ${errMsg(err)}`);
        return refuseStream(req, res, 3, "malformed");
      }
    }
    let resp: { status: number; headers: Record<string, string>; body: Buffer };
    try {
      resp = await this.upstream(path, forwardHeaders(req.headers), forwardBody);
    } catch (err) {                                                     // post-forward failure (transport / response too large) — commit unknown
      if (err instanceof ByteCapExceeded) this.capsHit.add(err.which);
      if (kind === "submit") this.submits.push({ kind: "ambiguous", reason: errMsg(err) });
      if (!res.headersSent) grpcWebStatus(res, 14, "upstream");
      return;
    }
    if (kind === "submit") this.submits.push(classifySubmit(resp));     // success | ambiguous
    // Hold the concurrency token until the response is delivered (finish) or the client drops (close) —
    // releasing on res.end() alone lets a non-reading client keep buffered responses off-budget. If the
    // client already dropped DURING the upstream wait, `close` already fired: resolve now, else the submit
    // would be stuck in inFlightSubmits forever (drain → spurious timeout despite the digest being recorded).
    await new Promise<void>((resolve) => {
      if (res.destroyed) return resolve();
      res.once("finish", resolve);
      res.once("close", resolve);
      res.writeHead(resp.status, resp.headers);
      res.end(resp.body);                                              // relay verbatim (incl. the digest we unioned in)
    });
  }

  private upstream(path: string, headers: Record<string, string>, body: Buffer): Promise<{ status: number; headers: Record<string, string>; body: Buffer }> {
    const maxResponseBytes = this.opts.caps.maxResponseBytes;
    return new Promise((resolve, reject) => {
      // No per-request/inactivity timeout (rev 13): the two overarching bounds — the confirmer-side phase
      // deadline (during the attack) and the drain deadline (after the boundary) — are the only timers.
      const up = httpRequest(
        { host: this.opts.upstreamHost, port: this.opts.upstreamPort, method: "POST", path, headers },
        (r) => {
          const chunks: Buffer[] = [];
          let total = 0;
          // Attach error/aborted FIRST: the `data` listener below resumes the stream, and an already-broken
          // response can emit `error` immediately — an unhandled `error` event would crash the process.
          r.on("error", reject);                                        // response stream broke — settle, never hang
          r.on("aborted", () => reject(new Error("response aborted")));
          r.on("end", () => resolve({ status: r.statusCode ?? 502, headers: relay(r.headers), body: Buffer.concat(chunks) }));
          r.on("data", (c) => {
            total += (c as Buffer).length;
            if (total > maxResponseBytes) { reject(new ByteCapExceeded("response-bytes")); r.destroy(); up.destroy(); return; }
            chunks.push(c as Buffer);
          });
        },
      );
      up.on("error", reject);
      up.end(body);
    });
  }
}

function relay(h: IncomingMessage["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) if (typeof v === "string" && k !== "transfer-encoding" && k !== "connection") out[k] = v;
  return out;
}

// ── confirmVisible: grader-side (host), NOT part of the proxy ────────────────────────────────────────
// Before POST, block until every drained digest is locally visible to the snapshot reads (the measured
// ~170ms index lag, spec §7.1). Pure over a client + digests, so it unit-tests without a localnet and
// drops into the confirmer unchanged. The confirmer calls it only when drain.kind === "complete".

export interface ConfirmVisibleResult { confirmed: string[]; kind: "complete" | "timeout" }

interface VisibilityClient {
  core: { waitForTransaction(o: { digest: string; timeout?: number; signal?: AbortSignal }): Promise<unknown> };
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), ms); });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

export async function confirmVisible(
  client: VisibilityClient,
  digests: readonly string[],
  opts: { perDigestMs: number; overallMs: number },
): Promise<ConfirmVisibleResult> {
  const controller = new AbortController();   // shared: abort at the boundary cancels every outstanding wait
  const confirmed: string[] = [];
  let done = false;
  const one = (digest: string): Promise<boolean> =>
    withTimeout(
      client.core.waitForTransaction({ digest, timeout: opts.perDigestMs, signal: controller.signal }),
      opts.perDigestMs,
    )
      .then(() => { if (!done) confirmed.push(digest); return true; })   // a late resolve after `done` must not mutate the return
      .catch(() => false);   // per-digest bound: a digest that never indexes doesn't hang the batch
  const all = Promise.all(digests.map(one)).then((oks) => oks.every(Boolean));
  const complete = await withTimeout(all, opts.overallMs).catch(() => false);
  done = true;
  controller.abort();        // cancel any still-running SDK waits (real client honors the signal)
  return { confirmed: [...confirmed], kind: complete ? "complete" : "timeout" };   // copy — never hand back a live array
}
