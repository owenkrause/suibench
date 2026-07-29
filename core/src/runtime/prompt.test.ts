// Integrity-invariant coverage for buildAuditorPrompt: for each config the
// assembler must emit the load-bearing bits — a non-empty prompt, the output
// schema/JSON block, and the network-appropriate execution instruction (real
// committed exec on devnet vs read-only dry-run on mainnet). Presence checks, not
// byte-matching, so they survive a future wording revision.
import { describe, it, expect } from "vitest";
import {
  buildAuditorPrompt,
  type AuditorPromptConfig,
} from "./prompt.js";

const MODULE_SOURCE = `module challenge::vault { public fun withdraw() {} }`;
const STATIC_MODULES = [
  { name: "vault", source: `module challenge::vault { public fun a() {} }` },
  { name: "admin", source: `module challenge::admin { public fun b() {} }` },
];
const ROOT_CAUSES = ["withdraw lacks a per-account balance check."];
const ENV = {
  rpcUrl: "http://127.0.0.1:9000",
  faucetUrl: "http://127.0.0.1:9123",
  packageId: "0xPKG",
  attackerAddress: "0xATTACKER",
  adminAddress: "0xADMIN",
  userAddress: "0xUSER",
};

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

const configs: { name: string; config: AuditorPromptConfig; net: "devnet" | "mainnet" }[] = [
  {
    name: "module / devnet",
    net: "devnet",
    config: {
      kind: "module",
      moduleName: "vault",
      moduleSource: MODULE_SOURCE,
      packageId: "0xPKG",
      rpcUrl: ENV.rpcUrl,
      network: "devnet",
      env: ENV,
    },
  },
  {
    name: "module / mainnet",
    net: "mainnet",
    config: {
      kind: "module",
      moduleName: "vault",
      moduleSource: MODULE_SOURCE,
      packageId: "0xPKG",
      rpcUrl: ENV.rpcUrl,
      network: "mainnet",
      env: ENV,
    },
  },
  {
    name: "entry / devnet",
    net: "devnet",
    config: {
      kind: "entry",
      entryName: "capability_leak",
      moduleNames: ["vault", "admin"],
      packageId: "0xPKG",
      rpcUrl: ENV.rpcUrl,
      network: "devnet",
      env: ENV,
    },
  },
  {
    name: "entry / mainnet",
    net: "mainnet",
    config: {
      kind: "entry",
      entryName: "capability_leak",
      moduleNames: ["vault", "admin"],
      packageId: "0xPKG",
      rpcUrl: ENV.rpcUrl,
      network: "mainnet",
      env: ENV,
    },
  },
  {
    name: "static-entry",
    net: "devnet", // static entry feeds the (devnet) confirmer — real execution later
    config: {
      kind: "static-entry",
      entryName: "capability_leak",
      modules: STATIC_MODULES,
    },
  },
  {
    name: "patch / devnet",
    net: "devnet",
    config: {
      kind: "patch",
      entryName: "capability_leak",
      moduleNames: ["vault", "admin"],
      rootCauses: ROOT_CAUSES,
      packageId: "0xPKG",
      rpcUrl: ENV.rpcUrl,
      env: ENV,
    },
  },
  {
    name: "static-patch",
    net: "devnet",
    config: {
      kind: "static-patch",
      entryName: "capability_leak",
      modules: STATIC_MODULES,
      rootCauses: ROOT_CAUSES,
    },
  },
];

describe("buildAuditorPrompt — integrity invariants", () => {
  for (const { name, config, net } of configs) {
    describe(name, () => {
      const prompt = buildAuditorPrompt(config);

      it("emits a non-empty prompt", () => {
        expect(prompt.trim().length).toBeGreaterThan(0);
      });

      const isPatch =
        config.kind === "patch" || config.kind === "static-patch";
      it("declares an output schema / JSON block", () => {
        expect(hasOutputSchema(prompt, isPatch)).toBe(true);
      });

      it("carries the network-appropriate execution instruction", () => {
        if (config.kind === "patch" || config.kind === "static-patch") {
          // patch mode emits a patch contract, not an exploit-execution mode.
          expect(prompt).toMatch(/patch\.json/);
          return;
        }
        if (net === "mainnet") {
          // read-only: dry-run / simulate, nothing commits on-chain.
          expect(prompt).toMatch(/dry-run|simulate|nothing executes/i);
        } else {
          // devnet / confirmer-fed: real, committed local execution.
          expect(prompt).toMatch(
            /signAndExecuteTransaction|real, committed|real execution|confirmer/i,
          );
        }
      });
    });
  }
});

describe("minimal-exploit reporting protocol", () => {
  const PROTOCOL = "Report each DISTINCT vulnerability as its own finding";

  for (const { name, config } of configs) {
    if (!["entry / devnet", "entry / mainnet", "static-entry"].includes(name)) {
      continue;
    }
    it(`${name} states the protocol`, () => {
      expect(buildAuditorPrompt(config)).toContain(PROTOCOL);
    });
  }

  it("is entry-agnostic — identical text regardless of entryName", () => {
    const base = configs.find((c) => c.name === "entry / devnet")!.config;
    if (base.kind !== "entry") throw new Error("expected an entry config");
    const a = buildAuditorPrompt({ ...base, entryName: "alpha_entry" });
    const b = buildAuditorPrompt({ ...base, entryName: "beta_entry" });
    expect(a).toContain(PROTOCOL);
    expect(b).toContain(PROTOCOL);
  });

  it("is absent from patch prompts (scoped to hunting)", () => {
    const patch = configs.find((c) => c.name === "patch / devnet")!.config;
    expect(buildAuditorPrompt(patch)).not.toContain(PROTOCOL);
  });
});
