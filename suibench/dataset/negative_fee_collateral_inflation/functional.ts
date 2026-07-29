// Functional (legit-behavior) check for `negative_fee_collateral_inflation` — see
// ../sources/perp.move.
//
// Exploit: settle a NEGATIVE fee of 900 (bounded only by magnitude), pays a legit positive fee then withdraws — nets +50, must NOT trip.
// collateral 100 -> 1000, then withdraw 1000 — draining the vault.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
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
      }) => Promise<unknown>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

async function findEx(ctx: FunctionalContext): Promise<string> {
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
          c.objectType === `${ctx.packageId}::perp::Exchange` &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: Exchange not found");
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const ex = await findEx(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const fee = tx.moveCall({
    target: `${ctx.packageId}::perp::make_fee`,
    arguments: [tx.pure.u64(50), tx.pure.bool(false)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::perp::settle_fee`,
    arguments: [tx.object(ex), fee],
  });
  const c = tx.moveCall({
    target: `${ctx.packageId}::perp::withdraw`,
    arguments: [tx.object(ex), tx.pure.u64(50)],
  });
  tx.transferObjects([c], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

export const functional = attack;
