import { PUBLISHED_VERSION, manifest } from "../../../server/version.js";

export const prerender = false;

export const GET = () =>
  new Response(JSON.stringify(manifest()), {
    headers: { "content-type": "application/json", "x-dataset-version": PUBLISHED_VERSION },
  });
