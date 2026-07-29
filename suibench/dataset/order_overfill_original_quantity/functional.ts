// Functional (legit-behavior) check for `order_overfill_original_quantity` — see
// ../sources/orderbook.move.
//
// Benign taker: the maker's order (quantity 10_000) has already been filled for 9_000, so
// only 1_000 legitimately remains. A fair taker fills exactly the remaining 1_000 and
// receives 1_000 base — a legitimate trade that must NOT trip the check. The over-fill
// (matching the full 10_000 against a nearly-exhausted order) is what the check flags; a
// fair remaining fill nets only 1_000, well under the threshold.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
    getOwnedObjects(i: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
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
      }) => Promise<unknown>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

async function findCreated(
  ctx: FunctionalContext,
  objectType: string,
): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (c.type === "created" && c.objectType === objectType && c.objectId)
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(`functional: object of type ${objectType} not found`);
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const order = await findCreated(ctx, `${ctx.packageId}::orderbook::Order`);
  const manager = await findCreated(
    ctx,
    `${ctx.packageId}::orderbook::Manager`,
  );
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [base] = tx.moveCall({
    target: `${ctx.packageId}::orderbook::take`,
    arguments: [tx.object(order), tx.object(manager), tx.pure.u64(1000)],
  });
  tx.transferObjects([base], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

export const functional = attack;
