// Integrity-invariant coverage for buildAuditorPrompt. The prompt space is a
// 2×2 of {audit, patch} × {harnessed, static}; for each the assembler must emit
// the load-bearing bits: a non-empty prompt, the right output schema, gRPC (never
// JSON-RPC) client guidance, the minimal-exploit protocol on audit prompts only,
// and — for static arms — an explicit "no execution tools" instruction. Presence
// checks, not byte-matching, so they survive a wording revision.
import { describe, it, expect } from "vitest";
import {
  buildAuditorPrompt,
  ATTACK_CONTEXT_CONTRACT,
  type AuditorPromptConfig,
} from "./prompt.js";

const STATIC_MODULES = [
  { name: "vault", source: `module challenge::vault { public fun a() {} }` },
  { name: "admin", source: `module challenge::admin { public fun b() {} }` },
];
const ROOT_CAUSES = ["withdraw lacks a per-account balance check."];

/** A fenced JSON output block is present: the finding shape for audit configs, or
 *  the patched-sources shape for patch configs. */
function hasOutputSchema(prompt: string, isPatch: boolean): boolean {
  if (!/```json/.test(prompt)) return false;
  if (isPatch) return /patchedSources/.test(prompt) && /patch\.json/.test(prompt);
  return (
    /"id"/.test(prompt) &&
    /"severity"/.test(prompt) &&
    (/findings\.json/.test(prompt) || /"exploitScript"/.test(prompt))
  );
}

interface Case {
  name: string;
  harness: "harnessed" | "static";
  isPatch: boolean;
  config: AuditorPromptConfig;
}

const configs: Case[] = [
  {
    name: "entry",
    harness: "harnessed",
    isPatch: false,
    config: {
      kind: "entry",
      entryName: "capability_leak",
      moduleNames: ["vault", "admin"],
      packageId: "0xPKG",
    },
  },
  {
    name: "static-entry",
    harness: "static",
    isPatch: false,
    config: {
      kind: "static-entry",
      entryName: "capability_leak",
      modules: STATIC_MODULES,
    },
  },
  {
    name: "patch",
    harness: "harnessed",
    isPatch: true,
    config: {
      kind: "patch",
      entryName: "capability_leak",
      moduleNames: ["vault", "admin"],
      rootCauses: ROOT_CAUSES,
      packageId: "0xPKG",
    },
  },
  {
    name: "static-patch",
    harness: "static",
    isPatch: true,
    config: {
      kind: "static-patch",
      entryName: "capability_leak",
      modules: STATIC_MODULES,
      rootCauses: ROOT_CAUSES,
    },
  },
];

describe("buildAuditorPrompt — integrity invariants", () => {
  for (const { name, config, harness, isPatch } of configs) {
    describe(name, () => {
      const prompt = buildAuditorPrompt(config);

      it("emits a non-empty prompt", () => {
        expect(prompt.trim().length).toBeGreaterThan(0);
      });

      it("declares an output schema / JSON block", () => {
        expect(hasOutputSchema(prompt, isPatch)).toBe(true);
      });

      it("carries the correct execution instruction", () => {
        if (isPatch) {
          expect(prompt).toMatch(/patch\.json/);
        } else {
          // audit: real, committed local execution via the confirmer.
          expect(prompt).toMatch(
            /signAndExecuteTransaction|real, committed|confirmer/i,
          );
        }
      });

      if (harness === "static") {
        it("tells a static run it has no execution tools", () => {
          expect(prompt).toMatch(/no execution tools|no bash/i);
        });
      }
    });
  }
});

describe("Sui client guidance", () => {
  for (const { name, config } of configs) {
    const prompt = buildAuditorPrompt(config);

    it(`${name} never directs the agent to the JSON-RPC client`, () => {
      expect(prompt).not.toContain("SuiJsonRpcClient");
      expect(prompt).not.toContain("@mysten/sui/jsonRpc");
    });

    // Every arm that ships SDK guidance names the gRPC client; only static-patch
    // (a blind fix, no exploit) carries none.
    if (config.kind !== "static-patch") {
      it(`${name} uses the gRPC client`, () => {
        expect(prompt).toContain("SuiGrpcClient");
      });
    }
  }

  it("points the harnessed audit at the in-container gRPC docs", () => {
    const entry = configs.find((c) => c.name === "entry")!.config;
    const prompt = buildAuditorPrompt(entry);
    expect(prompt).toContain("node_modules/@mysten/sui/docs");
    expect(prompt).toContain("clients/grpc.md");
  });

  it("documents native object discovery for executable entry scripts", () => {
    const entry = configs.find((c) => c.name === "entry")!.config;
    expect(buildAuditorPrompt(entry)).toContain("ctx.chain.findCreatedObjects");
  });
});

describe("minimal-exploit reporting protocol", () => {
  const PROTOCOL = "Report each DISTINCT vulnerability as its own finding";

  for (const { name, config, isPatch } of configs) {
    it(`${name} ${isPatch ? "omits" : "states"} the protocol`, () => {
      const prompt = buildAuditorPrompt(config);
      if (isPatch) expect(prompt).not.toContain(PROTOCOL);
      else expect(prompt).toContain(PROTOCOL);
    });
  }

  it("is entry-agnostic — identical text regardless of entryName", () => {
    const base = configs.find((c) => c.name === "entry")!.config;
    if (base.kind !== "entry") throw new Error("expected an entry config");
    const a = buildAuditorPrompt({ ...base, entryName: "alpha_entry" });
    const b = buildAuditorPrompt({ ...base, entryName: "beta_entry" });
    expect(a).toContain(PROTOCOL);
    expect(b).toContain(PROTOCOL);
  });
});

// --- attack(ctx) contract ↔ least-privilege runtime consistency ---
// Parity grading is blind to this: it runs GOLD exploits (authored attacker-only),
// so a prompt that promised admin/user keypairs would only mis-grade MODEL exploits.
// The runtime (src/adapters/runner.ts) hands the ATTACK phase only the attacker
// keypair + public addresses — never admin/user keypairs. This pins the prompt to that.

/** Top-level property names declared in the `attack(ctx: { ... })` type literal in
 *  the exploit contract (excludes the nested `chain` sub-methods). */
function declaredAttackCtxFields(contract: string): Set<string> {
  const marker = "attack(ctx: {";
  const start = contract.indexOf(marker);
  if (start < 0) throw new Error("attack(ctx) type literal not found in contract");
  const fields = new Set<string>();
  let depth = 1; // just inside the ctx object's opening brace
  let token = "";
  for (let i = start + marker.length; i < contract.length && depth > 0; i++) {
    const c = contract[i];
    if (c === "{") { depth++; token = ""; }
    else if (c === "}") { depth--; token = ""; }
    else if (depth === 1 && (c === ":" || c === "(")) {
      const name = token.trim();
      if (/^[A-Za-z_]\w*$/.test(name)) fields.add(name);
      token = "";
    } else if (depth === 1 && (c === ";" || c === "\n")) {
      token = "";
    } else if (depth === 1) {
      token += c;
    }
  }
  return fields;
}

describe("attack(ctx) contract ↔ runtime consistency", () => {
  // Keep in sync with the attack-phase ctx built in src/adapters/runner.ts
  // (trustedPhase === false): attacker keypair + public facts, NO admin/user keypairs.
  const RUNTIME_ATTACK_CTX_FIELDS = new Set([
    "client",
    "chain",
    "packageId",
    "attacker",
    "attackerAddress",
    "adminAddress",
    "userAddress",
  ]);

  it("declares exactly the runtime attack-phase fields — never admin/user keypairs", () => {
    const declared = declaredAttackCtxFields(ATTACK_CONTEXT_CONTRACT);
    expect(declared.has("admin")).toBe(false);
    expect(declared.has("user")).toBe(false);
    expect(declared).toEqual(RUNTIME_ATTACK_CTX_FIELDS);
  });
});
