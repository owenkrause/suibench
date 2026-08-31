// Decontamination guard (S7, prompt channel): the entry's directory name states
// its bug class (e.g. `liquidation_seize_uncapped`), so it must never reach the
// model-visible prompt. Two guards: the built prompt carries no entry's dir name,
// and the call site still passes the neutral label (catches a revert).
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAuditorPrompt } from "./prompt.js";
import { loadEntry, loadSource } from "../dataset/index.js";
import { PROMPT_TARGET_LABEL } from "./policies.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DATASET = resolve(HERE, "../../dataset");

describe("prompt decontamination", () => {
  const names = readdirSync(DATASET, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);

  for (const name of names) {
    it(`${name}: directory name absent from the model prompt`, () => {
      const entry = loadEntry(resolve(DATASET, name));
      const modules = loadSource(entry)
        .files.filter((f) => f.path.endsWith(".move"))
        .map((f) => ({ name: f.path, source: f.contents }));
      const rootCauses = entry.manifest.vulns.map((v) => v.root_cause);
      const prompts = [
        buildAuditorPrompt({ kind: "static-entry", entryName: PROMPT_TARGET_LABEL, modules }),
        buildAuditorPrompt({ kind: "static-patch", entryName: PROMPT_TARGET_LABEL, modules, rootCauses }),
      ];
      for (const p of prompts) expect(p).not.toContain(entry.target);
    });
  }

  it("the label is neutral and the call site does not pass the dir name", () => {
    expect(names).not.toContain(PROMPT_TARGET_LABEL);
    const src = readFileSync(resolve(HERE, "policies.ts"), "utf-8");
    expect(src).not.toMatch(/entryName:\s*entry\.target/);
  });
});
