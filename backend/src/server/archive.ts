// Gzip-tar archives built from in-memory MoveFile[] for the download routes.
// node-tar is filesystem-oriented, so we materialize files under a scratch
// dir (named after the entry id, so the archive extracts with that prefix)
// and tar the whole tree, always cleaning the scratch dir up.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import * as tar from "tar";
import type { MoveFile } from "core";

// tar's `Pack` return type is AsyncIterable at runtime (it's a Minipass
// stream) but its .d.ts doesn't fully implement NodeJS.ReadableStream, so we
// type the parameter as the narrower interface we actually use.
async function collectStream(stream: AsyncIterable<Buffer | string>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function writeEntryFiles(root: string, id: string, files: MoveFile[]): void {
  for (const f of files) {
    const dest = join(root, id, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.contents);
  }
}

export async function archiveEntry(id: string, files: MoveFile[]): Promise<Buffer> {
  const tmp = mkdtempSync(join(tmpdir(), "suibench-archive-"));
  try {
    writeEntryFiles(tmp, id, files);
    const stream = tar.create({ gzip: true, cwd: tmp, portable: true }, [id]);
    return await collectStream(stream);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export async function archiveCorpus(
  entries: { id: string; files: MoveFile[] }[],
  datasetVersion: string,
): Promise<Buffer> {
  const tmp = mkdtempSync(join(tmpdir(), "suibench-corpus-"));
  try {
    for (const e of entries) writeEntryFiles(tmp, e.id, e.files);
    writeFileSync(join(tmp, "DATASET_VERSION"), datasetVersion);
    const names = [...entries.map((e) => e.id), "DATASET_VERSION"];
    const stream = tar.create({ gzip: true, cwd: tmp, portable: true }, names);
    return await collectStream(stream);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
