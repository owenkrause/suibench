import { it, expect } from "vitest";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { CHAL_ID_RE } from "./manifest.js";

const DATASET = join(import.meta.dirname, "../../dataset");
const dirs = readdirSync(DATASET, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(join(DATASET, d.name, "entry.json")))
  .map((d) => d.name);

it("every entry has a well-formed chal_ id", () => {
  for (const d of dirs) {
    const id = JSON.parse(readFileSync(join(DATASET, d, "entry.json"), "utf-8")).id;
    expect(CHAL_ID_RE.test(id), `${d}: ${id}`).toBe(true);
  }
});
it("chal_ ids are unique across the corpus", () => {
  const ids = dirs.map((d) => JSON.parse(readFileSync(join(DATASET, d, "entry.json"), "utf-8")).id);
  expect(new Set(ids).size).toBe(ids.length);
});
