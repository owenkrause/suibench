// parseReports/parsePatch — suibench's own findings.json/patch.json parsers.
// core/runtime's runAgentLoop parses nothing, so each consumer owns turning what
// the model left in the sandbox into its own result shape. A fake in-memory
// Sandbox stands in for the container — no docker needed for these tests.
import { describe, expect, it } from "vitest";
import { SandboxFileNotFoundError } from "core";
import type { ExecResult, Exploit, Sandbox } from "core";
import { AgentError } from "core/runtime";
import { parseReports, parsePatch } from "./parse.js";

function fakeSandbox(seed: Record<string, string> = {}): Sandbox & {
  files: Map<string, string>;
} {
  const files = new Map<string, string>(Object.entries(seed));
  return {
    files,
    async exec(cmd: string): Promise<ExecResult> {
      return { stdout: `ran: ${cmd}`, stderr: "", exitCode: 0 };
    },
    async writeFile(path: string, content: string): Promise<void> {
      files.set(path, content);
    },
    async copyOut(path: string): Promise<Buffer> {
      const v = files.get(path);
      if (v === undefined) throw new SandboxFileNotFoundError(path);
      return Buffer.from(v, "utf-8");
    },
    async teardown() {},
  };
}

/** A sandbox whose copyOut fails for a reason other than "file not found" —
 * e.g. a container dying mid-read. */
function dyingSandbox(): Sandbox {
  return {
    async exec(cmd: string): Promise<ExecResult> {
      return { stdout: `ran: ${cmd}`, stderr: "", exitCode: 0 };
    },
    async writeFile(): Promise<void> {},
    async copyOut(): Promise<Buffer> {
      throw new Error("container died");
    },
    async teardown() {},
  };
}

describe("parseReports", () => {
  it("reads findings.json + its exploit script into {exploits, findings}", async () => {
    const sandbox = fakeSandbox({
      "findings.json": JSON.stringify([
        {
          id: "one",
          module: "pkg::m",
          severity: "high",
          title: "Drainable pool",
          description: "no auth check",
          exploitScript: "exploit-one.mts",
        },
      ]),
      "exploit-one.mts": "export async function attack(ctx){}",
    });

    const { exploits, findings } = await parseReports(sandbox);

    expect(exploits).toHaveLength(1);
    expect(exploits[0].finding).toEqual({
      id: "one",
      module: "pkg::m",
      severity: "high",
      title: "Drainable pool",
      description: "no auth check",
    });
    expect(exploits[0].script).toEqual({
      path: "exploit-one.mts",
      contents: "export async function attack(ctx){}",
    });
    expect(findings).toEqual(exploits.map((e: Exploit) => e.finding));
  });

  it("returns empty when findings.json is missing", async () => {
    const sandbox = fakeSandbox();
    expect(await parseReports(sandbox)).toEqual({ exploits: [], findings: [] });
  });

  it("returns empty when findings.json is malformed JSON", async () => {
    const sandbox = fakeSandbox({ "findings.json": "not json {{{" });
    expect(await parseReports(sandbox)).toEqual({ exploits: [], findings: [] });
  });

  it("returns empty when findings.json is a non-array JSON value", async () => {
    const sandbox = fakeSandbox({ "findings.json": JSON.stringify({ id: "one" }) });
    expect(await parseReports(sandbox)).toEqual({ exploits: [], findings: [] });
  });

  it("drops rows with no string id", async () => {
    const sandbox = fakeSandbox({
      "findings.json": JSON.stringify([
        { module: "pkg::m", severity: "high", title: "t", description: "d" },
      ]),
    });
    expect(await parseReports(sandbox)).toEqual({ exploits: [], findings: [] });
  });

  it("defaults severity/module/title/description and falls back to exploit-<id>.mts when exploitScript is absent, empty script when file missing", async () => {
    const sandbox = fakeSandbox({
      "findings.json": JSON.stringify([{ id: "two" }]),
    });

    const { exploits, findings } = await parseReports(sandbox);

    expect(exploits).toHaveLength(1);
    expect(exploits[0].finding).toEqual({
      id: "two",
      module: "",
      severity: "medium",
      title: "",
      description: "",
    });
    expect(exploits[0].script).toEqual({ path: "exploit-two.mts", contents: "" });
    expect(findings).toEqual([exploits[0].finding]);
  });

  it("ignores an unrecognized severity value and falls back to medium", async () => {
    const sandbox = fakeSandbox({
      "findings.json": JSON.stringify([{ id: "three", severity: "apocalyptic" }]),
    });
    const { exploits } = await parseReports(sandbox);
    expect(exploits[0].finding.severity).toBe("medium");
  });

  it("wraps a non-ENOENT copyOut failure in AgentError instead of the raw error", async () => {
    await expect(parseReports(dyingSandbox())).rejects.toThrow(AgentError);
  });
});

describe("parsePatch", () => {
  it("reads patch.json and each named source into a MoveFile[]", async () => {
    const sandbox = fakeSandbox({
      "patch.json": JSON.stringify({
        patchedSources: ["vault.move", "nested/pool.move"],
      }),
      "target/sources/vault.move": "module c::vault { /* fixed */ }",
      "target/sources/pool.move": "module c::pool { /* fixed */ }",
    });

    const files = await parsePatch(sandbox);

    expect(files).toEqual([
      { path: "vault.move", contents: "module c::vault { /* fixed */ }" },
      { path: "pool.move", contents: "module c::pool { /* fixed */ }" },
    ]);
  });

  it("returns [] when patch.json is missing", async () => {
    const sandbox = fakeSandbox();
    expect(await parsePatch(sandbox)).toEqual([]);
  });

  it("returns [] when patch.json is malformed JSON", async () => {
    const sandbox = fakeSandbox({ "patch.json": "not json {{{" });
    expect(await parsePatch(sandbox)).toEqual([]);
  });

  it("returns [] when patchedSources is absent or not an array", async () => {
    const sandbox = fakeSandbox({ "patch.json": JSON.stringify({}) });
    expect(await parsePatch(sandbox)).toEqual([]);

    const sandbox2 = fakeSandbox({
      "patch.json": JSON.stringify({ patchedSources: "vault.move" }),
    });
    expect(await parsePatch(sandbox2)).toEqual([]);
  });

  it("filters non-string entries out of patchedSources", async () => {
    const sandbox = fakeSandbox({
      "patch.json": JSON.stringify({ patchedSources: ["vault.move", 42, null] }),
      "target/sources/vault.move": "module c::vault {}",
    });
    expect(await parsePatch(sandbox)).toEqual([
      { path: "vault.move", contents: "module c::vault {}" },
    ]);
  });

  it("skips a listed source that isn't actually in the sandbox", async () => {
    const sandbox = fakeSandbox({
      "patch.json": JSON.stringify({ patchedSources: ["ghost.move"] }),
    });
    expect(await parsePatch(sandbox)).toEqual([]);
  });

  it("reads at target/sources/<basename>, not the sandbox root, even if a same-named file exists at root", async () => {
    const sandbox = fakeSandbox({
      "patch.json": JSON.stringify({ patchedSources: ["vault.move"] }),
      "vault.move": "module c::vault { /* stale root copy, must be ignored */ }",
      "target/sources/vault.move": "module c::vault { /* patched */ }",
    });
    expect(await parsePatch(sandbox)).toEqual([
      { path: "vault.move", contents: "module c::vault { /* patched */ }" },
    ]);
  });

  it("wraps a non-ENOENT copyOut failure in AgentError instead of the raw error", async () => {
    await expect(parsePatch(dyingSandbox())).rejects.toThrow(AgentError);
  });
});
