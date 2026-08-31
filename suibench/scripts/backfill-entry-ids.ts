// One-shot: give every entry.json a committed chal_ id if it lacks one. Idempotent.
import { readdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { CHAL_ID_RE } from "../src/dataset/manifest.js";

const DATASET = join(import.meta.dirname, "../dataset");
const used = new Set<string>();
const mint = () => { let s: string; do { s = "chal_" + randomBytes(4).toString("hex"); } while (used.has(s)); used.add(s); return s; };

for (const d of readdirSync(DATASET)) {
  const p = join(DATASET, d, "entry.json");
  if (!existsSync(p)) continue;
  const j = JSON.parse(readFileSync(p, "utf-8"));
  if (typeof j.id === "string" && CHAL_ID_RE.test(j.id)) { used.add(j.id); continue; }
  const out = { id: mint(), ...j };            // id first for readability
  writeFileSync(p, JSON.stringify(out, null, 2) + "\n");
  console.log(`${d}: ${out.id}`);
}
