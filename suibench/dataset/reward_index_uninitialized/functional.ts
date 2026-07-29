// Functional (legit-behavior) check for `reward_index_uninitialized` — see
// ../sources/spool.move.
//
// Benign: the legitimate long-term staker (admin, who staked before the reward accrued)
// claims their earned rewards. This exercises the claim path a correct patch preserves
// and does not touch the attacker's balance, so the attacker-gain check stays false.
import { Transaction } from "@mysten/sui/transactions";

interface Ctx {
  client: {
    queryTransactionBlocks(i: {
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
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  admin: unknown;
  adminAddress: string;
}

async function findSpool(ctx: Ctx): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (
          c.type === "created" &&
          c.objectType === `${ctx.packageId}::spool::Spool` &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: Spool not found");
}

export async function attack(ctx: Ctx): Promise<void> {
  const spool = await findSpool(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const reward = tx.moveCall({
    target: `${ctx.packageId}::spool::claim`,
    arguments: [tx.object(spool)],
  });
  tx.transferObjects([reward], ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: admin claim failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
