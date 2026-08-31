import type { APIRoute } from "astro";
import { getGrade } from "../../../../server/grading-runner.js";
import { ensureReady } from "../../../../server/init.js";
import { toSubmitterView } from "../../../../server/score-view.js";

export const prerender = false;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function json(status: number, obj: unknown): Response {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}

export const GET: APIRoute = async ({ params }) => {
  // Reject non-UUID ids before ensureReady()/getGrade — the id column is
  // `uuid`, so a malformed id would otherwise make Postgres throw (-> 500).
  // This check needs no DB, so it runs first.
  if (!params.id || !UUID_RE.test(params.id)) {
    return json(404, { error: "unknown job" });
  }
  await ensureReady();
  const row = await getGrade(params.id);
  if (!row) return json(404, { error: "unknown job" });
  return json(200, {
    state: row.state,
    error: row.error,
    score: row.state === "done" && row.score ? toSubmitterView(row.score) : null,
  });
};
