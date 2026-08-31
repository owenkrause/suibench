import { describe, expect, it } from "vitest";
import type { ChainDelta, CheckEvidence } from "core";
import { check } from "./check.js";

const PACKAGE = "0xabc";
const ATTACKER = "0xa11ce";
const ADMIN = "0xadd";
const USER = "0xbee";
const CAMPAIGN_A = "0xca";
const CAMPAIGN_B = "0xcb";
const WHITELIST_A = "0x1a";
const WHITELIST_B = "0x1b";
const WHITELIST_C = "0x1c";

const A = "whitelist-unbound-campaign";
const B = "whitelist-add-member-unauthorized";
const C = "whitelist-create-unauthorized";

const EMPTY_DELTA: ChainDelta = {
  pre: { balances: { byAddress: {} }, objects: { ownerOf: {}, byId: {} } },
  post: { balances: { byAddress: {} }, objects: { ownerOf: {}, byId: {} } },
};

function evidence(
  transactions: CheckEvidence["attackTransactions"],
): CheckEvidence {
  return { attackTransactions: transactions };
}

function created(json: Record<string, unknown>, packageId = PACKAGE) {
  return { type: `${packageId}::launchpad::WhitelistCreated`, json };
}

function memberAdded(json: Record<string, unknown>, packageId = PACKAGE) {
  return { type: `${packageId}::launchpad::WhitelistMemberAdded`, json };
}

function investment(json: Record<string, unknown>, packageId = PACKAGE) {
  return { type: `${packageId}::launchpad::Investment`, json };
}

const unboundInvestment = {
  actor: ATTACKER,
  whitelist_id: WHITELIST_B,
  campaign_id: CAMPAIGN_A,
  campaign_admin: ADMIN,
  whitelist_campaign_id: CAMPAIGN_B,
  amount: "1000000",
};

const unauthorizedAdd = {
  actor: ATTACKER,
  whitelist_id: WHITELIST_A,
  whitelist_admin: ADMIN,
  campaign_id: CAMPAIGN_A,
  member: ATTACKER,
};

const adminWhitelistInvestment = {
  actor: ATTACKER,
  whitelist_id: WHITELIST_A,
  campaign_id: CAMPAIGN_A,
  campaign_admin: ADMIN,
  whitelist_campaign_id: CAMPAIGN_A,
  amount: "1000000",
};

const unauthorizedCreation = {
  actor: ATTACKER,
  whitelist_id: WHITELIST_C,
  whitelist_admin: ATTACKER,
  campaign_id: CAMPAIGN_A,
  campaign_admin: ADMIN,
};

const attackerWhitelistAdd = {
  actor: ATTACKER,
  whitelist_id: WHITELIST_C,
  whitelist_admin: ATTACKER,
  campaign_id: CAMPAIGN_A,
  member: ATTACKER,
};

const attackerWhitelistInvestment = {
  actor: ATTACKER,
  whitelist_id: WHITELIST_C,
  campaign_id: CAMPAIGN_A,
  campaign_admin: ADMIN,
  whitelist_campaign_id: CAMPAIGN_A,
  amount: "1000000",
};

function run(attackEvidence: CheckEvidence) {
  return check(
    EMPTY_DELTA,
    { packageId: PACKAGE, attackerAddress: ATTACKER, adminAddress: ADMIN },
    attackEvidence,
  ).witnesses;
}

describe("whitelist_campaign_unbound checker", () => {
  it("witnesses only the unbound whitelist/campaign investment", () => {
    expect(
      run(evidence([{ digest: "a", status: "success", events: [investment(unboundInvestment)] }])),
    ).toEqual([A]);
  });

  it("witnesses only unauthorized membership on the admin whitelist followed by its investment", () => {
    expect(
      run(evidence([
        { digest: "add", status: "success", events: [memberAdded(unauthorizedAdd)] },
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
      ])),
    ).toEqual([B]);
  });

  it("witnesses only an attacker-created whitelist followed by its legitimate attacker-admin member add and investment", () => {
    expect(
      run(evidence([
        { digest: "create", status: "success", events: [created(unauthorizedCreation)] },
        { digest: "add", status: "success", events: [memberAdded(attackerWhitelistAdd)] },
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ])),
    ).toEqual([C]);
  });

  it("rejects an investment that preceded the unauthorized whitelist membership", () => {
    expect(
      run(evidence([
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
        { digest: "add", status: "success", events: [memberAdded(unauthorizedAdd)] },
      ])),
    ).toEqual([]);
  });

  it("rejects an investment that preceded the unauthorized whitelist creation", () => {
    expect(
      run(evidence([
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
        { digest: "create", status: "success", events: [created(unauthorizedCreation)] },
      ])),
    ).toEqual([]);
  });

  it.each([
    {
      name: "B forward order in one transaction",
      attackEvidence: evidence([
        { digest: "b-forward", status: "success", events: [memberAdded(unauthorizedAdd), investment(adminWhitelistInvestment)] },
      ]),
      witnesses: [B],
    },
    {
      name: "B reverse order in one transaction",
      attackEvidence: evidence([
        { digest: "b-reverse", status: "success", events: [investment(adminWhitelistInvestment), memberAdded(unauthorizedAdd)] },
      ]),
      witnesses: [],
    },
    {
      name: "C forward order in one transaction",
      attackEvidence: evidence([
        { digest: "c-forward", status: "success", events: [created(unauthorizedCreation), memberAdded(attackerWhitelistAdd), investment(attackerWhitelistInvestment)] },
      ]),
      witnesses: [C],
    },
    {
      name: "C reverse order in one transaction",
      attackEvidence: evidence([
        { digest: "c-reverse", status: "success", events: [investment(attackerWhitelistInvestment), memberAdded(attackerWhitelistAdd), created(unauthorizedCreation)] },
      ]),
      witnesses: [],
    },
  ])("uses $name", ({ attackEvidence, witnesses }) => {
    expect(run(attackEvidence)).toEqual(witnesses);
  });

  it("accumulates the three independent mechanisms", () => {
    expect(
      run(evidence([
        { digest: "a", status: "success", events: [investment(unboundInvestment)] },
        { digest: "b-add", status: "success", events: [memberAdded(unauthorizedAdd)] },
        { digest: "b-invest", status: "success", events: [investment(adminWhitelistInvestment)] },
        { digest: "c-create", status: "success", events: [created(unauthorizedCreation)] },
        { digest: "c-add", status: "success", events: [memberAdded(attackerWhitelistAdd)] },
        { digest: "c-invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ])),
    ).toEqual([A, B, C]);
  });

  it.each([
    {
      name: "a malformed identifier",
      attackEvidence: evidence([
        { digest: "malformed-id", status: "success", events: [investment({ ...unboundInvestment, whitelist_id: "not-an-id" })] },
      ]),
    },
    {
      name: "an overlong identifier",
      attackEvidence: evidence([
        { digest: "overlong-id", status: "success", events: [investment({ ...unboundInvestment, whitelist_id: `0x${"a".repeat(65)}` })] },
      ]),
    },
    {
      name: "a zero investment amount",
      attackEvidence: evidence([
        { digest: "zero", status: "success", events: [investment({ ...unboundInvestment, amount: "0" })] },
      ]),
    },
    {
      name: "a malformed investment amount",
      attackEvidence: evidence([
        { digest: "malformed-amount", status: "success", events: [investment({ ...unboundInvestment, amount: "nope" })] },
      ]),
    },
    {
      name: "an event emitted by another actor",
      attackEvidence: evidence([
        { digest: "actor", status: "success", events: [investment({ ...unboundInvestment, actor: USER })] },
      ]),
    },
    {
      name: "an event from another package",
      attackEvidence: evidence([
        { digest: "package", status: "success", events: [investment(unboundInvestment, "0xdef")] },
      ]),
    },
    {
      name: "an event emitted by a failed transaction",
      attackEvidence: evidence([
        { digest: "failed", status: "failure", events: [investment(unboundInvestment)] },
      ]),
    },
  ])("rejects $name", ({ attackEvidence }) => {
    expect(run(attackEvidence)).toEqual([]);
  });

  it.each([
    {
      name: "B when the membership event is from another actor",
      attackEvidence: evidence([
        { digest: "add", status: "success", events: [memberAdded({ ...unauthorizedAdd, actor: USER })] },
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
      ]),
    },
    {
      name: "B when the membership event is from another package",
      attackEvidence: evidence([
        { digest: "add", status: "success", events: [memberAdded(unauthorizedAdd, "0xdef")] },
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
      ]),
    },
    {
      name: "B when the membership transaction failed",
      attackEvidence: evidence([
        { digest: "add", status: "failure", events: [memberAdded(unauthorizedAdd)] },
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
      ]),
    },
    {
      name: "C when the creation event is from another actor",
      attackEvidence: evidence([
        { digest: "create", status: "success", events: [created({ ...unauthorizedCreation, actor: USER })] },
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ]),
    },
    {
      name: "C when the creation event is from another package",
      attackEvidence: evidence([
        { digest: "create", status: "success", events: [created(unauthorizedCreation, "0xdef")] },
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ]),
    },
    {
      name: "C when the creation transaction failed",
      attackEvidence: evidence([
        { digest: "create", status: "failure", events: [created(unauthorizedCreation)] },
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ]),
    },
  ])("rejects $name", ({ attackEvidence }) => {
    expect(run(attackEvidence)).toEqual([]);
  });

  it.each([
    {
      name: "B with a non-admin whitelist",
      attackEvidence: evidence([
        { digest: "add", status: "success", events: [memberAdded({ ...unauthorizedAdd, whitelist_admin: ATTACKER })] },
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
      ]),
    },
    {
      name: "B with a different whitelist ID",
      attackEvidence: evidence([
        { digest: "add", status: "success", events: [memberAdded({ ...unauthorizedAdd, whitelist_id: WHITELIST_B })] },
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
      ]),
    },
    {
      name: "B with a different campaign ID",
      attackEvidence: evidence([
        { digest: "add", status: "success", events: [memberAdded({ ...unauthorizedAdd, campaign_id: CAMPAIGN_B })] },
        { digest: "invest", status: "success", events: [investment(adminWhitelistInvestment)] },
      ]),
    },
    {
      name: "C with a different campaign admin",
      attackEvidence: evidence([
        { digest: "create", status: "success", events: [created({ ...unauthorizedCreation, campaign_admin: USER })] },
        { digest: "add", status: "success", events: [memberAdded(attackerWhitelistAdd)] },
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ]),
    },
    {
      name: "C with a different whitelist ID",
      attackEvidence: evidence([
        { digest: "create", status: "success", events: [created({ ...unauthorizedCreation, whitelist_id: WHITELIST_B })] },
        { digest: "add", status: "success", events: [memberAdded(attackerWhitelistAdd)] },
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ]),
    },
    {
      name: "C with a different campaign ID",
      attackEvidence: evidence([
        { digest: "create", status: "success", events: [created({ ...unauthorizedCreation, campaign_id: CAMPAIGN_B })] },
        { digest: "add", status: "success", events: [memberAdded(attackerWhitelistAdd)] },
        { digest: "invest", status: "success", events: [investment(attackerWhitelistInvestment)] },
      ]),
    },
  ])("rejects $name", ({ attackEvidence }) => {
    expect(run(attackEvidence)).toEqual([]);
  });
});
