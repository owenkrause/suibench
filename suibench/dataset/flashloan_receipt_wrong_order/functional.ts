// Benign: a legitimate flash loan — borrow from V and repay back into V (the correct
// order). Nets nothing; must NOT trip the check. A correct patch preserves this path.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
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
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}
async function findOrder(ctx: Ctx, from: string): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: from },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (
          c.type === "created" &&
          c.objectType === `${ctx.packageId}::limit_order::LimitOrder` &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(`functional: LimitOrder from ${from} not found`);
}
export async function attack(ctx: Ctx): Promise<void> {
  const V = await findOrder(ctx, ctx.adminAddress);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [borrowed, receipt] = tx.moveCall({
    target: `${ctx.packageId}::limit_order::flash_loan`,
    arguments: [tx.object(V), tx.pure.u64(1000)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::limit_order::repay_flash_loan`,
    arguments: [tx.object(V), borrowed, receipt],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: legit flash loan failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
export const functional = attack;
