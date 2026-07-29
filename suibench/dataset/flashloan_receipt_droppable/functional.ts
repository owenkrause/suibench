// Benign: a legitimate flash loan — borrow L=1000 from the Pool and repay it back
// into the SAME pool in the same tx with the same borrowed coin. Nets nothing; must
// NOT trip the check. A correct patch (receipt with no abilities) preserves this path.
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
async function findPool(ctx: Ctx): Promise<string> {
  const prefix = `${ctx.packageId}::pool::Pool`;
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (c.type === "created" && c.objectType === prefix && c.objectId)
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: Pool not found");
}
export async function attack(ctx: Ctx): Promise<void> {
  const pool = await findPool(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [borrowed, receipt] = tx.moveCall({
    target: `${ctx.packageId}::pool::flash_loan`,
    arguments: [tx.object(pool), tx.pure.u64(1000)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::pool::repay_flash_loan`,
    arguments: [tx.object(pool), borrowed, receipt],
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
