import { exportEntry } from "suibench/dataset";
import { archiveCorpus } from "../../../server/archive.js";
import { PUBLISHED_VERSION, registry } from "../../../server/version.js";

export const prerender = false;

export const GET = async () => {
  const buf = await archiveCorpus(
    [...registry().values()].map((e) => ({ id: e.id, files: exportEntry(e) })),
    PUBLISHED_VERSION,
  );
  return new Response(new Uint8Array(buf), {
    headers: {
      "content-type": "application/gzip",
      "x-dataset-version": PUBLISHED_VERSION,
      "content-disposition": `attachment; filename="benchmark-${PUBLISHED_VERSION}.tar.gz"`,
    },
  });
};
