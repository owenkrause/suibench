import { describe, it, expect } from "vitest";
import {
  sanitize,
  type ExploitAttribution,
  type Observation,
  type SanitizedSource,
} from "./types.js";

describe("illegal states are unrepresentable", () => {
  it("an Observation cannot carry groundtruth", () => {
    const obs: Observation = {
      source: sanitize([]),
      tools: { bash: true, writeFile: true, references: true },
      env: { model: "m", effort: "medium" },
      // @ts-expect-error — contamination is unrepresentable: no groundtruth field
      groundtruth: { vulns: [] },
    };
    void obs;
  });

  it("a raw file list is not a SanitizedSource", () => {
    // @ts-expect-error — only `sanitize()` produces the branded type
    const src: SanitizedSource = { files: [] };
    void src;
  });

  it("requires labels exactly when attribution is attributed", () => {
    const attributed: ExploitAttribution = { kind: "attributed", labels: ["label-a"] };
    const refutedAttribution: ExploitAttribution = { kind: "refuted", labels: [] };
    const unattributed: ExploitAttribution = { kind: "unattributed", labels: [] };
    void attributed;
    void refutedAttribution;
    void unattributed;

    // @ts-expect-error — attributed states require at least one label
    const emptyAttributed: ExploitAttribution = { kind: "attributed", labels: [] };
    // @ts-expect-error — unattributed states cannot carry labels
    const labeledUnattributed: ExploitAttribution = { kind: "unattributed", labels: ["label-a"] };
    void emptyAttributed;
    void labeledUnattributed;
  });
});

describe("sanitize — the sole SanitizedSource minter", () => {
  it("produces a SanitizedSource carrying the files", () => {
    const src = sanitize([{ path: "a.move", contents: "module a {}" }]);
    expect(src.files).toHaveLength(1);
  });
});
