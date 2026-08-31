// Unit-tests the counterfactualBoundary FACTORY WITHOUT Docker. A FAKE `Grader`
// returns a scripted snapshot per variant mount; a snapshot-pure `Check` reduces
// the delta to a `CheckResult` via the `runCheck` authoring guard. The N+1 loop
// + base-refuted short-circuit + attribution are the KERNEL's
// (`runCounterfactuals` + `attribute`) — the factory only builds the variant
// mount and runs the check through `runCheck`, so these tests drive the kernel
// functions directly and assert the composition wires up correctly.
import { describe, it, expect } from "vitest";
import {
  sanitize,
  runCounterfactuals,
  attribute,
  type Grader,
  type GraderResult,
  type Mount,
  type MoveFile,
  type ChainSnapshot,
  type ChainDelta,
  type Check,
  type CheckParams,
  type CheckEvidence,
} from "core";
import {
  counterfactualBoundary,
  variantMount,
  type PatchedLabel,
  type BoundaryDeps,
} from "./counterfactual-boundary.js";

const PKG = "0xpkg";
const ATTACKER = "0xattacker";
const COIN = `${PKG}::asset::ASSET`;
const NO_EVIDENCE: CheckEvidence = { attackTransactions: [] };

function snap(attackerBalance: bigint): ChainSnapshot {
  return {
    balances: { byAddress: { [ATTACKER]: { [COIN]: attackerBalance } } },
    objects: { ownerOf: {}, byId: {} },
  };
}
const EMPTY = snap(0n);

/** attacker gained >= 400 of ASSET -> witnesses ["reward-pool-drain"], else []. */
const LABEL = "reward-pool-drain";
const check: Check = (delta: ChainDelta, params: CheckParams) => {
  const post = delta.post.balances.byAddress[params.attackerAddress]?.[COIN] ?? 0n;
  const pre = delta.pre.balances.byAddress[params.attackerAddress]?.[COIN] ?? 0n;
  return post - pre >= 400n ? { witnesses: [LABEL] } : { witnesses: [] };
};
const checkParams: CheckParams = { packageId: PKG, attackerAddress: ATTACKER };

// A patch overlays a marker source file the fake grader keys off.
const MARKER = "sources/patch_marker.move";
function label(id: string): PatchedLabel {
  return { id, patchFiles: [{ path: MARKER, contents: id }] };
}
const VULN: Mount = sanitize([{ path: "sources/m.move", contents: "module m {}" }]);
function mountHandle(mount: Mount): string | null {
  return mount.files.find((f) => f.path === MARKER)?.contents ?? null;
}

const readScript = (p: string): MoveFile => ({ path: p, contents: "attack" });

/** Fake Grader: handle -> attacker post balance. Records each variant it graded.
 *  Returns a ChainDelta with an EMPTY pre (the grader owns the post-setup
 *  baseline; these entries seed nothing) and the scripted post, PLUS the per-boot
 *  params and (empty, by default) attack-phase evidence — matching the real
 *  Grader port. */
function fakeGrader(table: Record<string, bigint>, calls: string[]): Grader {
  return {
    async runOnMount(mount: Mount, _script: MoveFile): Promise<GraderResult> {
      const handle = mountHandle(mount) ?? "__base__";
      calls.push(handle);
      return {
        delta: { pre: EMPTY, post: snap(table[handle] ?? 0n) },
        params: checkParams,
        evidence: NO_EVIDENCE,
      };
    },
  };
}

function make(grader: Grader, overrides: Partial<BoundaryDeps> = {}) {
  return counterfactualBoundary({
    grader,
    vulnerableMount: VULN,
    readScript,
    check,
    allowedWitnessIds: [LABEL],
    label: "test-entry",
    ...overrides,
  });
}

describe("variantMount overlay", () => {
  it("null patch returns the vulnerable mount unchanged", () => {
    expect(variantMount(VULN, null)).toBe(VULN);
  });

  it("a patch REPLACES a matching source path in place, not appends", () => {
    const base = sanitize([{ path: "sources/m.move", contents: "OLD" }]);
    const patched = variantMount(base, {
      id: "fix",
      patchFiles: [{ path: "sources/m.move", contents: "NEW" }],
    });
    expect(patched.files).toHaveLength(1);
    expect(patched.files[0].contents).toBe("NEW");
  });

  it("a patch appends a new source path", () => {
    const patched = variantMount(VULN, label("h"));
    expect(patched.files.map((f) => f.path).sort()).toEqual([
      "sources/m.move",
      MARKER,
    ]);
  });
});

describe("counterfactualBoundary — runCheck plumbing", () => {
  it("passes the exact grader evidence object to the check's third argument", async () => {
    const evidenceRef: CheckEvidence = {
      attackTransactions: [{ digest: "0xd", status: "success", events: [] }],
    };
    let received: CheckEvidence | undefined;
    const evidenceCheck: Check = (_delta, _params, evidence) => {
      received = evidence;
      return { witnesses: [] };
    };
    const grader: Grader = {
      async runOnMount(): Promise<GraderResult> {
        return { delta: { pre: EMPTY, post: EMPTY }, params: checkParams, evidence: evidenceRef };
      },
    };
    const { boundary } = counterfactualBoundary({
      grader,
      vulnerableMount: VULN,
      readScript,
      check: evidenceCheck,
      allowedWitnessIds: [LABEL],
      label: "test-entry",
    });
    await boundary.runOnVariant("entry", "exploit.mts", null);
    expect(received).toBe(evidenceRef);
  });

  it("returns the canonical (sorted-copy) CheckResult, not a boolean", async () => {
    const twoWitnessCheck: Check = () => ({ witnesses: ["B", "A"] });
    const grader: Grader = {
      async runOnMount(): Promise<GraderResult> {
        return { delta: { pre: EMPTY, post: EMPTY }, params: checkParams, evidence: NO_EVIDENCE };
      },
    };
    const { boundary } = counterfactualBoundary({
      grader,
      vulnerableMount: VULN,
      readScript,
      check: twoWitnessCheck,
      allowedWitnessIds: ["A", "B"],
      label: "test-entry",
    });
    const result = await boundary.runOnVariant("entry", "exploit.mts", null);
    expect(result).toEqual({ witnesses: ["A", "B"] });
    expect(typeof result).not.toBe("boolean");
  });

  it("rejects a boolean check result cast through unknown", async () => {
    const booleanCheck = (() => false) as unknown as Check;
    const { boundary } = make(fakeGrader({ __base__: 1000n }, []), { check: booleanCheck });
    await expect(boundary.runOnVariant("entry", "exploit.mts", null)).rejects.toThrow(
      /must be an object/,
    );
  });

  it("rejects a witness id outside the allowed manifest set", async () => {
    const unknownIdCheck: Check = () => ({ witnesses: ["not-in-manifest"] });
    const { boundary } = make(fakeGrader({ __base__: 1000n }, []), { check: unknownIdCheck });
    await expect(boundary.runOnVariant("entry", "exploit.mts", null)).rejects.toThrow(
      /unknown id/,
    );
  });

  it("rejects a duplicate witness id", async () => {
    const duplicateCheck: Check = () => ({ witnesses: [LABEL, LABEL] });
    const { boundary } = make(fakeGrader({ __base__: 1000n }, []), { check: duplicateCheck });
    await expect(boundary.runOnVariant("entry", "exploit.mts", null)).rejects.toThrow(
      /duplicate/,
    );
  });

  it("baseProof holds the base snapshot only when the base witness set is nonempty", async () => {
    const calls: string[] = [];
    const grader = fakeGrader({ __base__: 1000n, A: 0n }, calls);
    const { boundary, baseProof } = make(grader);
    await boundary.runOnVariant("entry", "exploit.mts", null);
    const proof = baseProof.get("exploit.mts");
    expect(proof).not.toBeNull();
    expect(proof!.balances.byAddress[ATTACKER][COIN]).toBe(1000n);
  });

  it("baseProof stores null when the base witness set is empty", async () => {
    const calls: string[] = [];
    const grader = fakeGrader({ __base__: 100n }, calls);
    const { boundary, baseProof } = make(grader);
    await boundary.runOnVariant("entry", "exploit.mts", null);
    expect(baseProof.get("exploit.mts")).toBeNull();
  });
});

// --- kernel composition: the required attribution matrix -------------------
// A witness-table grader that reports, per variant handle, an independent
// witness set for labels A and B — encoded straight into the delta as
// per-label "witness:<id>" balances, so the check just reads membership. This
// lets one fake exercise every row of the spec's attribution matrix (composite
// switch, historical tripwire, genuine-both, patch-invariant, refuted), not
// just a single-label pass/fail threshold.
type WitnessSet = { A?: boolean; B?: boolean };
const AB_LABELS: PatchedLabel[] = [
  { id: "A", patchFiles: [{ path: MARKER, contents: "A" }] },
  { id: "B", patchFiles: [{ path: MARKER, contents: "B" }] },
];

function witnessSnap(w: WitnessSet): ChainSnapshot {
  return {
    balances: {
      byAddress: {
        [ATTACKER]: {
          "witness:A": w.A ? 1n : 0n,
          "witness:B": w.B ? 1n : 0n,
        },
      },
    },
    objects: { ownerOf: {}, byId: {} },
  };
}

const abCheck: Check = (delta, params) => {
  const post = delta.post.balances.byAddress[params.attackerAddress] ?? {};
  const witnesses: string[] = [];
  if ((post["witness:A"] ?? 0n) > 0n) witnesses.push("A");
  if ((post["witness:B"] ?? 0n) > 0n) witnesses.push("B");
  return { witnesses };
};

function witnessGrader(table: Record<string, WitnessSet>, calls: string[] = []): Grader {
  return {
    async runOnMount(mount: Mount, _script: MoveFile): Promise<GraderResult> {
      const handle = mountHandle(mount) ?? "__base__";
      calls.push(handle);
      return {
        delta: { pre: EMPTY, post: witnessSnap(table[handle] ?? {}) },
        params: checkParams,
        evidence: NO_EVIDENCE,
      };
    },
  };
}

function makeAB(grader: Grader) {
  return counterfactualBoundary({
    grader,
    vulnerableMount: VULN,
    readScript,
    check: abCheck,
    allowedWitnessIds: ["A", "B"],
    label: "matrix-entry",
  });
}

describe("counterfactualBoundary composed with the kernel — attribution matrix", () => {
  it("composite switch: base {A}, A-patch {B}, B-patch {A} -> attributes A only", async () => {
    const grader = witnessGrader({
      __base__: { A: true, B: false },
      A: { A: false, B: true },
      B: { A: true, B: false },
    });
    const { boundary } = makeAB(grader);
    const run = await runCounterfactuals("entry", "vuln-001", "exploit.mts", AB_LABELS, boundary);
    expect(run.base).toEqual({ witnesses: ["A"] });
    expect(attribute([run]).perExploit["vuln-001"]).toEqual({ kind: "attributed", labels: ["A"] });
  });

  it("historical tripwire shape: base {B}, A-patch {}, B-patch {} -> attributes B only", async () => {
    const grader = witnessGrader({
      __base__: { A: false, B: true },
      A: { A: false, B: false },
      B: { A: false, B: false },
    });
    const { boundary } = makeAB(grader);
    const run = await runCounterfactuals("entry", "vuln-001", "exploit.mts", AB_LABELS, boundary);
    expect(run.base).toEqual({ witnesses: ["B"] });
    expect(attribute([run]).perExploit["vuln-001"]).toEqual({ kind: "attributed", labels: ["B"] });
  });

  it("genuine both: base {A,B}, A-patch {B}, B-patch {A} -> attributes A and B", async () => {
    const grader = witnessGrader({
      __base__: { A: true, B: true },
      A: { A: false, B: true },
      B: { A: true, B: false },
    });
    const { boundary } = makeAB(grader);
    const run = await runCounterfactuals("entry", "vuln-001", "exploit.mts", AB_LABELS, boundary);
    expect(run.base).toEqual({ witnesses: ["A", "B"] });
    expect(attribute([run]).perExploit["vuln-001"]).toEqual({
      kind: "attributed",
      labels: ["A", "B"],
    });
  });

  it("patch-invariant A: base {A}, A-patch {A} -> unattributed regardless of B-patch", async () => {
    const grader = witnessGrader({
      __base__: { A: true, B: false },
      A: { A: true, B: false },
      B: { A: true, B: false },
    });
    const { boundary } = makeAB(grader);
    const run = await runCounterfactuals("entry", "vuln-001", "exploit.mts", AB_LABELS, boundary);
    expect(attribute([run]).perExploit["vuln-001"]).toEqual({ kind: "unattributed", labels: [] });
  });

  it("no witnessed mechanism: base {} -> refuted, NO per-label variant runs", async () => {
    const calls: string[] = [];
    const grader = witnessGrader({ __base__: { A: false, B: false } }, calls);
    const { boundary } = makeAB(grader);
    const run = await runCounterfactuals("entry", "vuln-001", "exploit.mts", AB_LABELS, boundary);
    expect(run.base).toEqual({ witnesses: [] });
    expect(attribute([run]).perExploit["vuln-001"]).toEqual({ kind: "refuted", labels: [] });
    expect(calls).toEqual(["__base__"]); // ONLY the base ran
  });
});
