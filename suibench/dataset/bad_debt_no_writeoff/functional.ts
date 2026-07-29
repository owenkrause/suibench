// Benign redemption: the attacker redeems only their FAIR socialized share
// (300 cTokens -> 300 ASSET, which is what a written-down rate would honor for
// the whole 500-cToken position). This is a legitimate partial exit that does
// NOT overpay relative to the pool's true redeemable value, so it must NOT trip
// the check. (Redeeming the full 500 at the overstated rate is the exploit; see
// exploits/bad-debt-no-writeoff.ts.)
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's
// AttackContext shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface Ctx {
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

async function findPool(ctx: Ctx): Promise<string> {
  const prefix = `${ctx.packageId}::lending_pool::Pool`;
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
async function findReceipt(ctx: Ctx): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.attackerAddress,
    filter: { StructType: `${ctx.packageId}::lending_pool::CTokenReceipt` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: attacker holds no CTokenReceipt");
  return id;
}

export async function attack(ctx: Ctx): Promise<void> {
  const pool = await findPool(ctx);
  const receipt = await findReceipt(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [payout, leftover] = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::redeem`,
    arguments: [tx.object(pool), tx.object(receipt), tx.pure.u64(300)],
  });
  tx.transferObjects([payout, leftover], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
