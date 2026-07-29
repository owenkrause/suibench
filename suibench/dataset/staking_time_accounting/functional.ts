// Functional (legit-behavior) check for `staking_time_accounting`.
//
// The legitimate flow is a plain stake -> unstake round-trip: a user stakes their
// ASSET, then exits early via `unstake`, which forfeits any reward and returns
// exactly the staked principal. This exercises that: the attacker stakes their
// 10,000 ASSET principal and immediately unstakes it, getting exactly 10,000 back
// — a net Δ of 0. It must NOT trip ./check.ts (threshold +900).
//
// Why no `claim_rewards` in the benign path: on the VULNERABLE package an honest
// single-receipt claim ALWAYS aborts (ENotEnoughStakingTime) because genuine
// staking time never reaches 168 hours in the seconds-scale window — there is no
// "legitimate claim" outcome to model on the unpatched code without invoking the
// merge-duplication bug. The honest legit flow is therefore a stake/unstake
// round-trip, which nets exactly 0 on both the vulnerable and the patched
// package. (An immediate honest claim would simply abort — see ./check.ts.)
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";
import { SUI_CLOCK_OBJECT_ID, normalizeStructTag } from "@mysten/sui/utils";

interface TxResult {
  $kind?: string;
  Transaction?: {
    effects?: { changedObjects?: { objectId: string; idOperation?: string }[] };
    objectTypes?: Record<string, string>;
  };
  FailedTransaction?: unknown;
}

interface FunctionalContext {
  client: {
    getOwnedObjects(input: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
    queryTransactionBlocks(input: {
      filter?: unknown;
      options?: unknown;
      cursor?: string | null;
    }): Promise<{
      data: {
        objectChanges?: {
          type: string;
          objectType?: string;
          objectId?: string;
        }[];
      }[];
      hasNextPage: boolean;
      nextCursor?: string | null;
    }>;
    core: {
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<TxResult>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const poolId = await findPool(ctx);
  const coinId = await findAttackerAssetCoin(ctx);
  const receiptType = `${ctx.packageId}::staking::StakeReceipt`;

  // --- stake the full 10,000 principal -> one receipt ---
  const stakeTx = new Transaction();
  stakeTx.setSender(ctx.attackerAddress);
  const receipt = stakeTx.moveCall({
    target: `${ctx.packageId}::staking::stake`,
    arguments: [
      stakeTx.object(poolId),
      stakeTx.object(coinId),
      stakeTx.object(SUI_CLOCK_OBJECT_ID),
    ],
  });
  stakeTx.transferObjects([receipt], ctx.attackerAddress);
  const stakeRes = await exec(ctx, stakeTx);
  const receiptIds = createdIds(stakeRes, receiptType);
  if (receiptIds.length !== 1)
    throw new Error("functional: expected 1 receipt from stake");

  // --- unstake it immediately -> exactly the principal back (net 0) ---
  const unstakeTx = new Transaction();
  unstakeTx.setSender(ctx.attackerAddress);
  const returned = unstakeTx.moveCall({
    target: `${ctx.packageId}::staking::unstake`,
    arguments: [unstakeTx.object(poolId), unstakeTx.object(receiptIds[0])],
  });
  unstakeTx.transferObjects([returned], ctx.attackerAddress);
  await exec(ctx, unstakeTx);
}

async function exec(
  ctx: FunctionalContext,
  tx: Transaction,
): Promise<TxResult> {
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true, objectTypes: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: a transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
  return res;
}

function createdIds(res: TxResult, structType: string): string[] {
  const tx = res.Transaction;
  if (!tx) return [];
  const types = tx.objectTypes ?? {};
  const want = normalizeStructTag(structType);
  const ids: string[] = [];
  for (const change of tx.effects?.changedObjects ?? []) {
    const got = types[change.objectId];
    if (
      change.idOperation === "Created" &&
      got &&
      normalizeStructTag(got) === want
    ) {
      ids.push(change.objectId);
    }
  }
  return ids;
}

async function findPool(ctx: FunctionalContext): Promise<string> {
  const poolType = `${ctx.packageId}::staking::StakingPool`;
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data) {
      for (const change of tx.objectChanges ?? []) {
        if (
          change.type === "created" &&
          change.objectType === poolType &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: could not locate the shared StakingPool");
}

async function findAttackerAssetCoin(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.attackerAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: attacker holds no ASSET coin");
  return id;
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
