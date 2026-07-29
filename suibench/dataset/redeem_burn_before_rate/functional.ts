// Benign: the attacker stakes their 1000 ASSET (minting 1000 shares) and then
// redeems a single share. With total_hawal = 2000, wal_out = 1 * 2000 / 1999 = 1
// (integer division) — a negligible payout. Net over the episode is ~-999 ASSET
// (they staked 1000 and pulled back 1), so this legitimate partial-redeem flow —
// which a correct patch preserves — must NOT trip the attacker-gain check.
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
          c.objectType === `${ctx.packageId}::liquid_staking::Pool` &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: Pool not found");
}
async function findCoin(ctx: Ctx): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.attackerAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: attacker holds no ASSET");
  return id;
}
export async function attack(ctx: Ctx): Promise<void> {
  const pool = await findPool(ctx);
  const coin = await findCoin(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  tx.moveCall({
    target: `${ctx.packageId}::liquid_staking::stake`,
    arguments: [tx.object(pool), tx.object(coin)],
  });
  const out = tx.moveCall({
    target: `${ctx.packageId}::liquid_staking::redeem`,
    arguments: [tx.object(pool), tx.pure.u64(1)],
  });
  tx.transferObjects([out], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: attacker stake/redeem failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
export const functional = attack;
