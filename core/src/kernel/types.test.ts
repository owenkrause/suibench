import { describe, it, expect } from "vitest";
import {
  sanitize,
  confirmed,
  refuted,
  falsePositive,
  type Exploit,
  type ChainSnapshot,
  type Observation,
  type SanitizedSource,
  type Verdict,
} from "./types.js";

const exploit: Exploit = {
  finding: {
    id: "vuln-001",
    module: "vault",
    severity: "critical",
    title: "unchecked withdraw",
    description: "attacker drains the vault",
  },
  script: {
    path: "exploit-001.mts",
    contents: "export async function attack() {}",
  },
};

const proof: ChainSnapshot = {
  balances: { byAddress: { "0xattacker": { "0x2::sui::SUI": 1_000n } } },
  objects: { ownerOf: { "0xvault": null }, byId: {} },
  events: { events: [] },
};

describe("illegal states are unrepresentable", () => {
  it("a confirmed verdict cannot omit its proof", () => {
    // @ts-expect-error — confirmed REQUIRES `proof`
    const bad: Verdict = { kind: "confirmed", exploit };
    void bad;
  });

  it("a confirmed verdict cannot omit its exploit", () => {
    // @ts-expect-error — confirmed REQUIRES `exploit`
    const bad: Verdict = { kind: "confirmed", proof };
    void bad;
  });

  it("an Observation cannot carry groundtruth", () => {
    const obs: Observation = {
      source: sanitize([]),
      tools: { bash: true, writeFile: true, references: true },
      env: { network: "devnet", model: "m", effort: "medium" },
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
});

describe("smart constructors build valid values", () => {
  it("confirmed carries exploit + proof", () => {
    const v = confirmed(exploit, proof);
    expect(v.kind).toBe("confirmed");
    if (v.kind === "confirmed") {
      expect(v.exploit).toBe(exploit);
      expect(v.proof).toBe(proof);
    }
  });

  it("refuted carries a reason", () => {
    const v = refuted(exploit, "exploit did not commit");
    expect(v).toEqual({
      kind: "refuted",
      exploit,
      reason: "exploit did not commit",
    });
  });

  it("false_positive carries only a reason", () => {
    const v = falsePositive("no exploit produced");
    expect(v).toEqual({
      kind: "false_positive",
      reason: "no exploit produced",
    });
  });

  it("sanitize produces a SanitizedSource carrying the files", () => {
    const src = sanitize([{ path: "a.move", contents: "module a {}" }]);
    expect(src.files).toHaveLength(1);
  });
});
