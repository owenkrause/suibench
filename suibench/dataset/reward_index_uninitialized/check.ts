// Snapshot-pure success predicate for `reward_index_uninitialized`.
//
// The exploit is a shared-Spool state transition: an already-accrued reward
// index stays fixed while a new account and its stake are added, and the pool's
// historical reward balance is consumed. These linked deltas identify the
// uninitialized checkpoint without depending on the attacker's net balance.
import {
  sharedObjectFields,
  type Check,
  type CheckResult,
} from "core";

const LABEL_ID = "reward-index-uninit" as const;

type RecordLike = Record<string, unknown>;

function asRecord(value: unknown): RecordLike | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as RecordLike)
    : null;
}

/** Parse RPC field values without allowing malformed values to throw. */
function parseBigInt(value: unknown): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) return null;
  } else if (typeof value === "string") {
    if (!/^\d+$/.test(value)) return null;
  } else {
    return null;
  }
  try {
    return BigInt(value as string | number | bigint);
  } catch {
    return null;
  }
}

function field(fields: RecordLike, name: string): bigint | null {
  return parseBigInt(fields[name]);
}

function balanceValue(fields: RecordLike, name: string): bigint | null {
  // Sui snapshots commonly flatten Balance<T> to its `value`; accept the
  // object form too so the checker remains independent of RPC serialization.
  const direct = parseBigInt(fields[name]);
  if (direct !== null) return direct;
  const balance = asRecord(fields[name]);
  return balance ? field(balance, "value") : null;
}

function tableSize(fields: RecordLike): bigint | null {
  const table = asRecord(fields.accounts);
  return table ? field(table, "size") : null;
}

export const check: Check = (delta, params): CheckResult => {
  const spoolType = `${params.packageId}::spool::Spool`;
  const pre = sharedObjectFields(delta.pre, spoolType);
  const post = sharedObjectFields(delta.post, spoolType);
  if (!pre || !post) return { witnesses: [] };

  const preRewardIndex = field(pre, "reward_index");
  const postRewardIndex = field(post, "reward_index");
  const preAccounts = tableSize(pre);
  const postAccounts = tableSize(post);
  const preStakedFunds = balanceValue(pre, "staked_funds");
  const postStakedFunds = balanceValue(post, "staked_funds");
  const preTotalStaked = field(pre, "total_staked");
  const postTotalStaked = field(post, "total_staked");
  const preRewards = balanceValue(pre, "rewards");
  const postRewards = balanceValue(post, "rewards");

  if (
    preRewardIndex === null ||
    postRewardIndex === null ||
    preAccounts === null ||
    postAccounts === null ||
    preStakedFunds === null ||
    postStakedFunds === null ||
    preTotalStaked === null ||
    postTotalStaked === null ||
    preRewards === null ||
    postRewards === null
  ) {
    return { witnesses: [] };
  }

  const stakedFundsDelta = postStakedFunds - preStakedFunds;
  const totalStakedDelta = postTotalStaked - preTotalStaked;
  const witnessed =
    preRewardIndex > 0n &&
    postRewardIndex === preRewardIndex &&
    postAccounts > preAccounts &&
    postStakedFunds > preStakedFunds &&
    totalStakedDelta === stakedFundsDelta &&
    postRewards < preRewards;

  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
