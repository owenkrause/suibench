// Gold-patch integrity gate: run every entry's OWN reference patch through the
// PATCH axis (compile + functional + exploit-defeated). verify:graders only ever
// runs the exploitation axis, where an always-aborting patch looks like success.
import { resolve } from "node:path";
import { loadEntry, loadSource, loadPatchFiles, loadCheck } from "../src/dataset/index.js";
import { overlayPatch } from "../src/bench/patch-driver.js";
import { makePatchGraderBoundary } from "../src/adapters/patch-grader.js";
import { SandboxManager } from "../src/adapters/sandbox.js";
import { boundedMap } from "../src/util/bounded.js";
import type { Check } from "core";

const CONCURRENCY = Number(process.env.SWEEP_CONCURRENCY ?? "5");
import { readdirSync } from "node:fs";
const DATASET = resolve(import.meta.dirname, "../dataset");
const names = process.argv.slice(2).length
  ? process.argv.slice(2)
  : readdirSync(DATASET, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
const skipped: string[] = [];
type Job = { name: string; vulnId: string; entry: ReturnType<typeof loadEntry>; check: Check };
const jobs: Job[] = [];

for (const name of names) {
  let entry;
  try { entry = loadEntry(resolve(import.meta.dirname, "../dataset", name)); }
  catch (e) { skipped.push(`${name} — load error: ${String(e).slice(0, 90)}`); continue; }
  if (entry.tier !== "confirmed") { skipped.push(`${name} — detect-tier (no check.ts)`); continue; }
  if (!entry.functionalPath) { skipped.push(`${name} — no functional.ts`); continue; }
  const check = await loadCheck(entry);
  for (const v of entry.manifest.vulns) {
    if (!entry.patches[v.id]) { skipped.push(`${name}/${v.id} — no patch dir`); continue; }
    jobs.push({ name, vulnId: v.id, entry, check });
  }
}

console.log(`gold-patch sweep: ${jobs.length} patch(es) across ${names.length} entries, concurrency=${CONCURRENCY}\n`);
const manager = new SandboxManager();
let done = 0;
try {
  const rows = await boundedMap(jobs, CONCURRENCY, async (j) => {
    try {
      const patchedMount = overlayPatch(loadSource(j.entry), loadPatchFiles(j.entry, j.vulnId));
      const b = makePatchGraderBoundary({ entry: j.entry, patchedMount, check: j.check, manager });
      const c = await b.compile();
      const f = c.compiles ? await b.runFunctional() : { passed: false, error: "did not compile" };
      const x = c.compiles ? await b.confirmExploit(j.vulnId) : { confirmed: true };
      const ok = c.compiles && f.passed && !x.confirmed;
      console.log(`  [${++done}/${jobs.length}] ${ok ? "PASS" : "FAIL"}  ${j.name}/${j.vulnId}`);
      return { ...j, ok, compiles: c.compiles, functional: f.passed, defeated: !x.confirmed,
               err: (f as any).error ?? (c as any).error };
    } catch (e) {
      console.log(`  [${++done}/${jobs.length}] ERROR ${j.name}/${j.vulnId}`);
      return { ...j, ok: false, error: String(e) };
    }
  });
  const bad = rows.filter((r: any) => !r.ok);
  if (bad.length > 0 || rows.length === 0) process.exitCode = 1;
  console.log(`\n===== ${rows.length - bad.length}/${rows.length} gold patches pass the patch axis =====`);
  for (const r of bad as any[]) {
    console.log(`\nFAIL  ${r.name} / ${r.vulnId}`);
    if (r.error) console.log(`      error: ${String(r.error).replace(/\s+/g, " ").slice(0, 240)}`);
    else {
      console.log(`      compiles=${r.compiles} functional=${r.functional} exploit_defeated=${r.defeated}`);
      if (r.err) console.log(`      ${String(r.err).replace(/\s+/g, " ").slice(0, 240)}`);
    }
  }
  console.log(`\n--- SKIPPED (${skipped.length}, not patch-gradable) ---`);
  for (const s of skipped) console.log(`  ${s}`);
} finally { await manager.teardownAll(); }
