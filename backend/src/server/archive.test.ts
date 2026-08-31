import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { describe, expect, it } from "vitest";
import { archiveCorpus, archiveEntry } from "./archive.js";

async function extract(buf: Buffer): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "archive-test-"));
  const tgz = join(dir, "out.tar.gz");
  writeFileSync(tgz, buf);
  await tar.x({ file: tgz, cwd: dir });
  return dir;
}

describe("archiveEntry", () => {
  it("archives an entry under its chal_ id dir", async () => {
    const buf = await archiveEntry("chal_7f3k9m2q", [{ path: "Move.toml", contents: "x" }]);
    const dir = await extract(buf);
    try {
      expect(readFileSync(join(dir, "chal_7f3k9m2q/Move.toml"), "utf-8")).toBe("x");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("archiveCorpus", () => {
  it("archives multiple entries plus a top-level DATASET_VERSION file", async () => {
    const buf = await archiveCorpus(
      [
        { id: "chal_aaaaaaaa", files: [{ path: "Move.toml", contents: "a" }] },
        { id: "chal_bbbbbbbb", files: [{ path: "Move.toml", contents: "b" }] },
      ],
      "deadbeef",
    );
    const dir = await extract(buf);
    try {
      expect(readFileSync(join(dir, "chal_aaaaaaaa/Move.toml"), "utf-8")).toBe("a");
      expect(readFileSync(join(dir, "chal_bbbbbbbb/Move.toml"), "utf-8")).toBe("b");
      expect(readFileSync(join(dir, "DATASET_VERSION"), "utf-8")).toBe("deadbeef");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
