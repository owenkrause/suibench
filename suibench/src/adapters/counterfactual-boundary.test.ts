// Unit-tests the counterfactualBoundary FACTORY WITHOUT Docker. A FAKE `Grader`
// returns a scripted snapshot per variant mount; a snapshot-pure `Check` reduces
// the delta. The N+1 loop + base=false short-circuit + attribution are the
// KERNEL's (`runCounterfactuals` + `attribute`) — the factory only builds the
// variant mount and reduces the delta, so these tests drive the kernel functions
// directly and assert the composition wires up correctly.
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
} from "core";
import {
  counterfactualBoundary,
  variantMount,
  type PatchedLabel,
} from "./counterfactual-boundary.js";

const PKG = "0xpkg";
const ATTACKER = "0xattacker";
const COIN = `${PKG}::asset::ASSET`;

function snap(attackerBalance: bigint): ChainSnapshot {
  return {
    balances: { byAddress: { [ATTACKER]: { [COIN]: attackerBalance } } },
    objects: { ownerOf: {}, byId: {} },
    events: { events: [] },
  };
}
const EMPTY = snap(0n);

/** attacker gained >= 400 of ASSET. */
const check: Check = (delta: ChainDelta, params: CheckParams): boolean => {
  const post = delta.post.balances.byAddress[params.attackerAddress]?.[COIN] ?? 0n;
  const pre = delta.pre.balances.byAddress[params.attackerAddress]?.[COIN] ?? 0n;
  return post - pre >= 400n;
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
 *  params (matching the real Grader port — the check reads them off the result). */
function fakeGrader(table: Record<string, bigint>, calls: string[]): Grader {
  return {
    async runOnMount(mount: Mount, _script: MoveFile): Promise<GraderResult> {
      const handle = mountHandle(mount) ?? "__base__";
      calls.push(handle);
      return { delta: { pre: EMPTY, post: snap(table[handle] ?? 0n) }, params: checkParams };
    },
  };
}

function make(grader: Grader) {
  return counterfactualBoundary({
    grader,
    vulnerableMount: VULN,
    readScript,
    check,
    label: "test-entry",
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

describe("counterfactualBoundary driven by the kernel", () => {
  it("base=true, patch A breaks it → attributes to A (via kernel runCounterfactuals+attribute)", async () => {
    const calls: string[] = [];
    const grader = fakeGrader({ __base__: 1000n, A: 0n, B: 1000n }, calls);
    const { boundary } = make(grader);
    const run = await runCounterfactuals(
      "entry",
      "vuln-001",
      "exploit.mts",
      [label("A"), label("B")],
      boundary,
    );
    const attribution = attribute([run]);
    expect(run.base).toBe(true);
    expect(attribution.perExploit["vuln-001"]).toEqual(["A"]);
    // one base + one per label — the loop is the kernel's, not ours.
    expect(calls.filter((c) => c === "__base__")).toHaveLength(1);
    expect(calls.sort()).toEqual(["A", "B", "__base__"]);
  });

  it("base=false → kernel short-circuits: NO per-label variant runs", async () => {
    const calls: string[] = [];
    const grader = fakeGrader({ __base__: 100n, A: 0n }, calls);
    const { boundary } = make(grader);
    const run = await runCounterfactuals(
      "entry",
      "vuln-001",
      "exploit.mts",
      [label("A")],
      boundary,
    );
    expect(run.base).toBe(false);
    expect(attribute([run]).perExploit["vuln-001"]).toEqual([]);
    expect(calls).toEqual(["__base__"]); // ONLY the base ran
  });

  it("baseProof holds the base snapshot only when the base run passed", async () => {
    const calls: string[] = [];
    const grader = fakeGrader({ __base__: 1000n, A: 0n }, calls);
    const { boundary, baseProof } = make(grader);
    await runCounterfactuals("entry", "vuln-001", "exploit.mts", [label("A")], boundary);
    const proof = baseProof.get("exploit.mts");
    expect(proof).not.toBeNull();
    expect(proof!.balances.byAddress[ATTACKER][COIN]).toBe(1000n);
  });

  it("patch-invariant (base=true, no patch breaks it) → empty attribution", async () => {
    const grader = fakeGrader({ __base__: 1000n, A: 1000n, B: 1000n }, []);
    const { boundary } = make(grader);
    const run = await runCounterfactuals(
      "entry",
      "vuln-001",
      "exploit.mts",
      [label("A"), label("B")],
      boundary,
    );
    expect(attribute([run]).perExploit["vuln-001"]).toEqual([]);
  });
});
