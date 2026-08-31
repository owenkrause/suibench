import type { APIRoute } from "astro";
import { exportEntry } from "suibench/dataset";
import { archiveEntry } from "../../../../server/archive.js";
import { PUBLISHED_VERSION, registry } from "../../../../server/version.js";

export const prerender = false;

export const GET: APIRoute = async ({ params }) => {
  const entry = registry().get(params.id!);
  if (!entry) return new Response("unknown entry", { status: 404 });
  const buf = await archiveEntry(entry.id, exportEntry(entry));
  return new Response(new Uint8Array(buf), {
    headers: {
      "content-type": "application/gzip",
      "x-dataset-version": PUBLISHED_VERSION,
      "content-disposition": `attachment; filename="${entry.id}.tar.gz"`,
    },
  });
};
