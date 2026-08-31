import type { APIRoute } from "astro";
import { CapacityError, submitGrade } from "../../../server/grading-runner.js";
import { ensureReady } from "../../../server/init.js";
import { MAX_REQUEST_BYTES, parseSubmission } from "../../../server/validate.js";

export const prerender = false;

function json(status: number, obj: unknown): Response {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}

export const POST: APIRoute = async ({ request }) => {
  // Reject on the declared Content-Length before buffering the body (or even
  // touching the DB via ensureReady) — a client can omit or lie about this
  // header, so the post-read Buffer.byteLength check below stays as a
  // backstop, but this precheck is what keeps an oversized request from ever
  // being fully read into memory.
  const len = Number(request.headers.get("content-length"));
  if (Number.isFinite(len) && len > MAX_REQUEST_BYTES) {
    return json(413, { error: "payload too large" });
  }

  await ensureReady();

  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf-8") > MAX_REQUEST_BYTES) {
    return json(413, { error: "payload too large" });
  }

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return json(400, { error: "invalid JSON" });
  }

  let parsed;
  try {
    parsed = parseSubmission(body);
  } catch (e) {
    return json(400, { error: (e as Error).message });
  }

  try {
    const { jobId } = await submitGrade(parsed);
    return json(202, { jobId });
  } catch (e) {
    if (e instanceof CapacityError) {
      return json(429, { error: e.message });
    }
    // Otherwise submitGrade throws only for validation (datasetVersion
    // mismatch, unknown entryId), and only before any DB write — a 400.
    return json(400, { error: (e as Error).message });
  }
};
