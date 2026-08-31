import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";
import { resolve } from "node:path";
import { loadEntry } from "./entry.js";
import { buildEntryRegistry, datasetVersion, discoverConfirmedEntries } from "./registry.js";

const DATASET = resolve(import.meta.dirname, "../../dataset");
const REPO_ROOT = execSync("git rev-parse --show-toplevel", { encoding: "utf-8" }).trim();

describe("buildEntryRegistry", () => {
  it("indexes by chal_ id", () => {
    const e = loadEntry(resolve(DATASET, "flash_loan_misuse"));
    const reg = buildEntryRegistry([e]);
    expect(reg.get(e.id)).toBe(e);
  });

  it("throws on a duplicate id", () => {
    const e = loadEntry(resolve(DATASET, "flash_loan_misuse"));
    expect(() => buildEntryRegistry([e, e])).toThrow(/duplicate/);
  });
});

describe("datasetVersion", () => {
  it("is a 40-char sha", () => {
    expect(datasetVersion(REPO_ROOT, "suibench/dataset")).toMatch(/^[0-9a-f]{40}$/);
  });
});

describe("discoverConfirmedEntries", () => {
  it("returns exactly the 36 confirmed-tier entries, excluding -patched dirs", () => {
    const entries = discoverConfirmedEntries(DATASET);
    expect(entries.length).toBe(36);
    expect(entries.every((e) => e.tier === "confirmed")).toBe(true);
    expect(entries.every((e) => !e.target.endsWith("-patched"))).toBe(true);
  });
});
