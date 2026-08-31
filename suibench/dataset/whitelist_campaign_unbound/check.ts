// Event-local predicates for three independent access-control failures in the
// launchpad. The success receipts bind each witness to the operation that
// committed it, rather than inferring a cause from aggregate campaign state.
import {
  type Check,
  type CheckResult,
  fieldAsBigInt,
  normalizeType,
  successfulMoveEvents,
} from "core";

const A = "whitelist-unbound-campaign" as const;
const B = "whitelist-add-member-unauthorized" as const;
const C = "whitelist-create-unauthorized" as const;

type Investment = {
  actor: string;
  whitelistId: string;
  campaignId: string;
  campaignAdmin: string;
  whitelistCampaignId: string;
  amount: bigint;
};

type MemberAdded = {
  actor: string;
  whitelistId: string;
  whitelistAdmin: string;
  campaignId: string;
  member: string;
};

type WhitelistCreated = {
  actor: string;
  whitelistId: string;
  whitelistAdmin: string;
  campaignId: string;
  campaignAdmin: string;
};

type AttackOrdinal = {
  transactionOrdinal: number;
  eventOrdinal: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function identifier(value: unknown): string | null {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) return null;
  if (value.slice(2).replace(/^0+/, "").length > 64) return null;
  return normalizeType(value);
}

function positiveInteger(fields: Record<string, unknown>, name: string): bigint | null {
  try {
    const value = fieldAsBigInt(fields, name);
    return value !== null && value > 0n ? value : null;
  } catch {
    return null;
  }
}

function investment(json: unknown): Investment | null {
  if (!isRecord(json)) return null;
  const actor = identifier(json.actor);
  const whitelistId = identifier(json.whitelist_id);
  const campaignId = identifier(json.campaign_id);
  const campaignAdmin = identifier(json.campaign_admin);
  const whitelistCampaignId = identifier(json.whitelist_campaign_id);
  const amount = positiveInteger(json, "amount");
  return actor && whitelistId && campaignId && campaignAdmin && whitelistCampaignId && amount
    ? { actor, whitelistId, campaignId, campaignAdmin, whitelistCampaignId, amount }
    : null;
}

function memberAdded(json: unknown): MemberAdded | null {
  if (!isRecord(json)) return null;
  const actor = identifier(json.actor);
  const whitelistId = identifier(json.whitelist_id);
  const whitelistAdmin = identifier(json.whitelist_admin);
  const campaignId = identifier(json.campaign_id);
  const member = identifier(json.member);
  return actor && whitelistId && whitelistAdmin && campaignId && member
    ? { actor, whitelistId, whitelistAdmin, campaignId, member }
    : null;
}

function whitelistCreated(json: unknown): WhitelistCreated | null {
  if (!isRecord(json)) return null;
  const actor = identifier(json.actor);
  const whitelistId = identifier(json.whitelist_id);
  const whitelistAdmin = identifier(json.whitelist_admin);
  const campaignId = identifier(json.campaign_id);
  const campaignAdmin = identifier(json.campaign_admin);
  return actor && whitelistId && whitelistAdmin && campaignId && campaignAdmin
    ? { actor, whitelistId, whitelistAdmin, campaignId, campaignAdmin }
    : null;
}

function orderedEvents<T>(
  evidence: Parameters<Check>[2],
  eventType: string,
  parse: (json: unknown) => T | null,
): (T & AttackOrdinal)[] {
  const accepted = new Set(successfulMoveEvents(evidence, eventType));
  const events: (T & AttackOrdinal)[] = [];
  evidence.attackTransactions.forEach((transaction, transactionOrdinal) => {
    transaction.events.forEach((event, eventOrdinal) => {
      if (!accepted.has(event)) return;
      const parsed = parse(event.json);
      if (parsed) events.push({ ...parsed, transactionOrdinal, eventOrdinal });
    });
  });
  return events;
}

function follows(later: AttackOrdinal, earlier: AttackOrdinal): boolean {
  return later.transactionOrdinal > earlier.transactionOrdinal
    || (later.transactionOrdinal === earlier.transactionOrdinal
      && later.eventOrdinal > earlier.eventOrdinal);
}

export const check: Check = (_delta, params, evidence): CheckResult => {
  const attacker = identifier(params.attackerAddress);
  const admin = identifier(params.adminAddress);
  if (!attacker || !admin) return { witnesses: [] };

  const investments = orderedEvents(
    evidence,
    `${params.packageId}::launchpad::Investment`,
    investment,
  );
  const additions = orderedEvents(
    evidence,
    `${params.packageId}::launchpad::WhitelistMemberAdded`,
    memberAdded,
  );
  const creations = orderedEvents(
    evidence,
    `${params.packageId}::launchpad::WhitelistCreated`,
    whitelistCreated,
  );

  const attackerInvestments = investments.filter(
    (event) => event.actor === attacker && event.campaignAdmin === admin,
  );
  const sawA = attackerInvestments.some(
    (event) => event.campaignId !== event.whitelistCampaignId,
  );
  const sawB = additions.some(
    (addition) => addition.actor === attacker
      && addition.member === attacker
      && addition.whitelistAdmin === admin
      && attackerInvestments.some(
        (event) => follows(event, addition)
          && event.whitelistId === addition.whitelistId
          && event.campaignId === addition.campaignId
          && event.whitelistCampaignId === addition.campaignId,
      ),
  );
  const sawC = creations.some(
    (creation) => creation.actor === attacker
      && creation.whitelistAdmin === attacker
      && creation.campaignAdmin === admin
      && attackerInvestments.some(
        (event) => follows(event, creation)
          && event.whitelistId === creation.whitelistId
          && event.campaignId === creation.campaignId
          && event.whitelistCampaignId === creation.campaignId,
      ),
  );

  return { witnesses: [...(sawA ? [A] : []), ...(sawB ? [B] : []), ...(sawC ? [C] : [])] };
};
