import { createHash } from "node:crypto";
import { sourceDigest } from "suibench/dataset";
import { describe, expect, it } from "vitest";
import { PUBLISHED_VERSION, manifest, registry } from "./version.js";

describe("version", () => {
  it("publishes a content-digest version + a manifest of confirmed-tier chal_ ids", () => {
    expect(PUBLISHED_VERSION).toMatch(/^[0-9a-f]{64}$/);

    // Independently recompute the digest from the registry's own entries to
    // prove PUBLISHED_VERSION is exactly the content fingerprint of what's served.
    const expected = createHash("sha256")
      .update(
        [...registry().values()]
          .map((e) => `${e.id}:${sourceDigest(e)}`)
          .sort()
          .join("\n"),
      )
      .digest("hex");
    expect(PUBLISHED_VERSION).toBe(expected);

    const m = manifest();
    expect(m.datasetVersion).toBe(PUBLISHED_VERSION);
    expect(m.entries.length).toBe(36);
    expect(
      m.entries.every((e) => /^chal_/.test(e.id) && /^[0-9a-f]{64}$/.test(e.sourceDigest)),
    ).toBe(true);
    expect(registry().size).toBe(36);
  });
});
