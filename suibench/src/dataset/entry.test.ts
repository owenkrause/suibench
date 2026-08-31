import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readdirSync, readFileSync } from "node:fs";
import ts from "typescript";
import type {
  ChainSnapshot,
  ChainDelta,
  ObjectState,
  VictimOutcome,
  CheckParams,
  CheckEvidence,
  MoveEventEvidence,
  AttackTransactionEvidence,
} from "core";
import { ownerAddress, runCheck } from "core";
import { loadEntry, loadCheck } from "./entry.js";
import { parseManifest } from "./manifest.js";

const DATASET = resolve(import.meta.dirname, "../../dataset");

const PKG = "0xpkg";
const ATTACKER = "0xattacker";
const ADMIN = "0xadmin";
const USER = "0xuser";

const NO_EVIDENCE: CheckEvidence = { attackTransactions: [] };

/** Hand-build a snapshot from balances, owned objects, and an optional victim. */
function snap(
  balances: Record<string, Record<string, bigint>>,
  objects: Record<string, ObjectState> = {},
  victim?: VictimOutcome,
): ChainSnapshot {
  const ownerOf: Record<string, string | null> = {};
  for (const [id, o] of Object.entries(objects)) ownerOf[id] = ownerAddress(o.owner);
  return {
    balances: { byAddress: balances },
    objects: { ownerOf, byId: objects },
    ...(victim ? { victim } : {}),
  };
}

describe("manifest validation", () => {
  it("rejects a duplicate vuln id", () => {
    const raw = JSON.stringify({
      vulns: [
        { id: "a", module: "m", title: "t", severity: "high", harm: "state", root_cause: "r" },
        { id: "a", module: "m", title: "t2", severity: "low", harm: "state", root_cause: "r" },
      ],
    });
    expect(() => parseManifest(raw, "x")).toThrow(/duplicate vuln id/);
  });

  it("rejects an invalid severity", () => {
    const raw = JSON.stringify({
      vulns: [
        { id: "a", module: "m", title: "t", severity: "sev", root_cause: "r" },
      ],
    });
    expect(() => parseManifest(raw, "x")).toThrow(/invalid severity/);
  });
});

describe("loadEntry surfaces the manifest chal_ id", () => {
  it("loadEntry surfaces the manifest chal_ id", () => {
    const e = loadEntry(resolve(DATASET, "flash_loan_misuse"));
    expect(e.id).toMatch(/^chal_[0-9a-z]{8}$/);
    expect(e.id).toBe(e.manifest.id);
  });
});

describe("loadEntry — the migrated entries load, validate, and map cleanly", () => {
  const entries = [
    "capability_leak",
    "deepbook_critbit_dos",
  ];

  for (const name of entries) {
    it(`${name}: manifest + exploits/patches map to real ids; confirmed-tier`, () => {
      const e = loadEntry(resolve(DATASET, name));
      expect(e.tier).toBe("confirmed");
      expect(e.checkPath).not.toBeNull();
      const ids = new Set(e.manifest.vulns.map((v) => v.id));
      for (const id of Object.keys(e.exploits)) expect(ids.has(id)).toBe(true);
      for (const id of Object.keys(e.patches)) expect(ids.has(id)).toBe(true);
      // every declared exploit/patch id resolved to a file/dir
      for (const v of e.manifest.vulns) {
        if (v.exploit) expect(e.exploits[v.id]).toBeDefined();
        if (v.patch) expect(e.patches[v.id]).toBeDefined();
      }
    });
  }

  it("shared_object_race ships a setup phase; deepbook ships a victim phase", () => {
    const sor = loadEntry(resolve(DATASET, "shared_object_race"));
    expect(sor.harness.setup).toBeDefined();
    const db = loadEntry(resolve(DATASET, "deepbook_critbit_dos"));
    expect(db.harness.victim).toBeDefined();
  });
});

// The core assertion of Task 9: each migrated check COMPILES (imports cleanly)
// and is SNAPSHOT-PURE — a pure `(ChainDelta, params, evidence) => CheckResult`
// decided from a hand-built ChainDelta, with no live client. Checks are invoked
// through `runCheck` with the entry's own manifest label IDs as the allowed
// witness set, and asserted by exact witness array.
describe("migrated checks are snapshot-pure against a hand-built ChainDelta", () => {
  const ADMIN_CAP: ObjectState = {
    owner: { AddressOwner: "" },
    type: `${PKG}::vault::AdminCap`,
    fields: {},
  };
  const cap = (owner: string): ObjectState => ({ ...ADMIN_CAP, owner: { AddressOwner: owner } });

  it("capability_leak: witnesses admincap-leak iff attacker AND admin both hold an AdminCap", async () => {
    const e = loadEntry(resolve(DATASET, "capability_leak"));
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const params: CheckParams = {
      packageId: PKG,
      attackerAddress: ATTACKER,
      adminAddress: ADMIN,
    };
    const pre: ChainDelta["pre"] = snap({}, { admin: cap(ADMIN) });

    // fresh mint: attacker + admin both hold a cap -> witnessed
    const minted: ChainDelta = {
      pre,
      post: snap({}, { admin: cap(ADMIN), attacker: cap(ATTACKER) }),
    };
    expect(
      runCheck(check, allowedWitnessIds, minted, params, NO_EVIDENCE).witnesses,
    ).toEqual(["admincap-leak"]);

    // transfer cheat: only attacker holds the (single) cap -> refuted
    const transferred: ChainDelta = {
      pre,
      post: snap({}, { attacker: cap(ATTACKER) }),
    };
    expect(
      runCheck(check, allowedWitnessIds, transferred, params, NO_EVIDENCE).witnesses,
    ).toEqual([]);
  });

  it("deepbook_critbit_dos: witnesses critbit-brick iff the victim aborts in is_left_child", async () => {
    const e = loadEntry(resolve(DATASET, "deepbook_critbit_dos"));
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const params: CheckParams = { packageId: PKG, attackerAddress: ATTACKER };
    const pre = snap({});
    const abortIn = (loc: string) =>
      `MoveAbort in 1st command, abort code: 7, in '${PKG}::critbit::${loc}' (instruction 10)`;

    // bricked: victim aborts in the labeled location -> exploit succeeded -> witnessed
    expect(
      runCheck(
        check,
        allowedWitnessIds,
        { pre, post: snap({}, {}, { status: "abort", message: abortIn("is_left_child") }) },
        params,
        NO_EVIDENCE,
      ).witnesses,
    ).toEqual(["critbit-brick"]);

    // patched: victim traversal completes -> refuted
    expect(
      runCheck(
        check,
        allowedWitnessIds,
        { pre, post: snap({}, {}, { status: "success", message: null }) },
        params,
        NO_EVIDENCE,
      ).witnesses,
    ).toEqual([]);

    // an UNRELATED abort (not the labeled assert) must NOT confirm
    expect(
      runCheck(
        check,
        allowedWitnessIds,
        { pre, post: snap({}, {}, { status: "abort", message: abortIn("remove_leaf") }) },
        params,
        NO_EVIDENCE,
      ).witnesses,
    ).toEqual([]);

    // a missing victim outcome (infra failure) fails closed
    expect(
      runCheck(
        check,
        allowedWitnessIds,
        { pre, post: snap({}, {}, undefined) },
        params,
        NO_EVIDENCE,
      ).witnesses,
    ).toEqual([]);
  });

  it("magna_vesting_div_by_zero: accepts the gRPC abort spelling at the labeled function", async () => {
    const e = loadEntry(resolve(DATASET, "magna_vesting_div_by_zero"));
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const params: CheckParams = { packageId: PKG, attackerAddress: ATTACKER };
    const pre = snap({});

    expect(
      runCheck(
        check,
        allowedWitnessIds,
        {
          pre,
          post: snap({}, {}, {
            status: "abort",
            message: `MoveAbort in 1st command, abort code: 0, in '${PKG}::vesting::calc_vested_piece_amount' (instruction 8)`,
          }),
        },
        params,
        NO_EVIDENCE,
      ).witnesses,
    ).toEqual(["vesting-div-by-zero"]);
  });
});

// Task 6: bad_debt_no_writeoff moves from an aggregate-gain OR predicate to an
// event-only multi-label check. A = "bad-debt-no-writeoff" (Redemption event,
// actual_payout > fair_written_off_payout); B = "collateral-release-no-repay"
// (CollateralRelease event, debt_remaining > 0 && collateral_released > 0).
// These synthetic-evidence cases are RED against the current aggregate-gain
// checker (it ignores `evidence` and reads snapshot balances/objects instead)
// and pin the exact witness sets the event-only checker must produce.
describe("bad_debt_no_writeoff: event-only multi-label check", () => {
  const ENTRY = resolve(DATASET, "bad_debt_no_writeoff");
  const REDEMPTION = `${PKG}::lending_pool::Redemption`;
  const RELEASE = `${PKG}::lending_pool::CollateralRelease`;

  const params: CheckParams = { packageId: PKG, attackerAddress: ATTACKER };
  const delta: ChainDelta = { pre: snap({}), post: snap({}) };

  const redemptionEvent = (
    overrides: Partial<{
      actor: unknown;
      ctokens_burned: unknown;
      actual_payout: unknown;
      fair_written_off_payout: unknown;
    }> = {},
    type = REDEMPTION,
  ): MoveEventEvidence => ({
    type,
    json: {
      actor: ATTACKER,
      ctokens_burned: 500,
      actual_payout: 500,
      fair_written_off_payout: 300,
      ...overrides,
    },
  });

  const releaseEvent = (
    overrides: Partial<{
      actor: unknown;
      debt_remaining: unknown;
      collateral_released: unknown;
    }> = {},
    type = RELEASE,
  ): MoveEventEvidence => ({
    type,
    json: {
      actor: ATTACKER,
      debt_remaining: 500,
      collateral_released: 700,
      ...overrides,
    },
  });

  const tx = (
    events: readonly MoveEventEvidence[],
    status: "success" | "failure" = "success",
    digest = "0xd1",
  ): AttackTransactionEvidence => ({ digest, status, events });

  const evidenceOf = (
    ...transactions: readonly AttackTransactionEvidence[]
  ): CheckEvidence => ({ attackTransactions: transactions });

  it("valid A redemption -> [A]", async () => {
    const e = loadEntry(ENTRY);
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const evidence = evidenceOf(tx([redemptionEvent()]));
    expect(
      runCheck(check, allowedWitnessIds, delta, params, evidence).witnesses,
    ).toEqual(["bad-debt-no-writeoff"]);
  });

  it("equal or lower actual_payout -> []", async () => {
    const e = loadEntry(ENTRY);
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const equalEvidence = evidenceOf(
      tx([redemptionEvent({ actual_payout: 300, fair_written_off_payout: 300 })]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, equalEvidence).witnesses,
    ).toEqual([]);
    const lowerEvidence = evidenceOf(
      tx([redemptionEvent({ actual_payout: 250, fair_written_off_payout: 300 })]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, lowerEvidence).witnesses,
    ).toEqual([]);
  });

  it("valid B collateral release -> [B]", async () => {
    const e = loadEntry(ENTRY);
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const evidence = evidenceOf(tx([releaseEvent()]));
    expect(
      runCheck(check, allowedWitnessIds, delta, params, evidence).witnesses,
    ).toEqual(["collateral-release-no-repay"]);
  });

  it("repaid/zero-collateral release -> []", async () => {
    const e = loadEntry(ENTRY);
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const repaidEvidence = evidenceOf(
      tx([releaseEvent({ debt_remaining: 0, collateral_released: 700 })]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, repaidEvidence).witnesses,
    ).toEqual([]);
    const zeroCollateralEvidence = evidenceOf(
      tx([releaseEvent({ debt_remaining: 500, collateral_released: 0 })]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, zeroCollateralEvidence)
        .witnesses,
    ).toEqual([]);
  });

  it("both successful events -> [A, B]", async () => {
    const e = loadEntry(ENTRY);
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const evidence = evidenceOf(tx([redemptionEvent(), releaseEvent()]));
    expect(
      runCheck(check, allowedWitnessIds, delta, params, evidence).witnesses,
    ).toEqual(["bad-debt-no-writeoff", "collateral-release-no-repay"]);
  });

  it("a fair redemption plus a profitable B event -> [B]; aggregate gain cannot manufacture A", async () => {
    const e = loadEntry(ENTRY);
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);
    const evidence = evidenceOf(
      tx([
        redemptionEvent({ actual_payout: 300, fair_written_off_payout: 300 }),
        releaseEvent(),
      ]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, evidence).witnesses,
    ).toEqual(["collateral-release-no-repay"]);
  });

  it("wrong package, wrong actor, failed tx, malformed JSON, absent evidence -> []", async () => {
    const e = loadEntry(ENTRY);
    const check = await loadCheck(e);
    const allowedWitnessIds = e.manifest.vulns.map((v) => v.id);

    // wrong package: event type from a different package address never matches
    // params.packageId, so successfulMoveEvents excludes it entirely.
    const wrongPackage = evidenceOf(
      tx([redemptionEvent({}, `0xother::lending_pool::Redemption`)]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, wrongPackage).witnesses,
    ).toEqual([]);

    // wrong actor: event's actor is not the attacker.
    const wrongActor = evidenceOf(
      tx([redemptionEvent({ actor: "0xsomeoneelse" })]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, wrongActor).witnesses,
    ).toEqual([]);

    // failed transaction: events on a failed tx never contribute.
    const failedTx = evidenceOf(tx([redemptionEvent()], "failure"));
    expect(
      runCheck(check, allowedWitnessIds, delta, params, failedTx).witnesses,
    ).toEqual([]);

    // malformed JSON: event payload is not a record.
    const malformed = evidenceOf(
      tx([{ type: REDEMPTION, json: "not-an-object" }]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, malformed).witnesses,
    ).toEqual([]);

    // malformed field: a well-formed record whose numeric field can't BigInt()
    // (exercises eventBigInt's try/catch, distinct from the non-record case above).
    const malformedField = evidenceOf(
      tx([redemptionEvent({ actual_payout: "not-a-number" })]),
    );
    expect(
      runCheck(check, allowedWitnessIds, delta, params, malformedField).witnesses,
    ).toEqual([]);

    // absent evidence: no attack transactions at all.
    expect(
      runCheck(check, allowedWitnessIds, delta, params, NO_EVIDENCE).witnesses,
    ).toEqual([]);
  });
});

// Style-agnostic corpus ID-drift gate. `tsconfig.checks.json` (`tsc -p`) owns
// type correctness and `verify:graders` owns empirical execution; this test
// owns neither — it only checks that every confirmed check.ts's SOURCE TEXT
// still spells out its own manifest label ids, literally, and no other
// entry's id. It reads with `typescript.createScanner` as a bare lexer
// (skipTrivia so comments are never scanned into tokens) and looks only at
// StringLiteral / NoSubstitutionTemplateLiteral token VALUES — never a
// Program or AST — so it imposes no opinion on arrow/function style, return
// annotations, type assertions, boolean unions, or early-return shape.
function collectStringLiterals(source: string): Set<string> {
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    /* skipTrivia */ true,
    ts.LanguageVariant.Standard,
    source,
  );
  const literals = new Set<string>();
  let token = scanner.scan();
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if (
      token === ts.SyntaxKind.StringLiteral ||
      token === ts.SyntaxKind.NoSubstitutionTemplateLiteral
    ) {
      literals.add(scanner.getTokenValue());
    }
    token = scanner.scan();
  }
  return literals;
}

describe("corpus ID-drift: every confirmed check.ts hard-codes its own manifest label ids and no other entry's", () => {
  it("visits exactly 36 confirmed checks / 39 labels and finds every id verbatim in its own check.ts's literals, and no foreign id", () => {
    const names = readdirSync(DATASET, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();

    // The foreign-id universe spans EVERY dataset manifest, confirmed AND
    // detect-tier alike — a check must never smuggle in an id that belongs to
    // an entry with no check.ts of its own.
    const allLabelIds = new Set<string>();
    const confirmed: { name: string; checkPath: string; labelIds: string[] }[] = [];
    let confirmedLabelCount = 0;

    for (const name of names) {
      const entry = loadEntry(resolve(DATASET, name));
      for (const vuln of entry.manifest.vulns) allLabelIds.add(vuln.id);
      if (entry.tier === "confirmed" && entry.checkPath) {
        const labelIds = entry.manifest.vulns.map((v) => v.id);
        confirmed.push({ name, checkPath: entry.checkPath, labelIds });
        confirmedLabelCount += labelIds.length;
      }
    }

    expect(confirmed.length).toBe(36);
    expect(confirmedLabelCount).toBe(39);

    for (const { name, checkPath, labelIds } of confirmed) {
      const literals = collectStringLiterals(readFileSync(checkPath, "utf-8"));
      for (const id of labelIds) {
        expect(
          literals.has(id),
          `${name}/check.ts: expected a hard-coded literal for its own label id "${id}"`,
        ).toBe(true);
      }
      const foreign = [...allLabelIds].filter(
        (id) => !labelIds.includes(id) && literals.has(id),
      );
      expect(
        foreign,
        `${name}/check.ts: contains foreign label id(s) ${foreign.join(", ")}`,
      ).toEqual([]);
    }
  });
});
