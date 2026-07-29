import { Transaction } from "@mysten/sui/transactions";

// Fixed redeem amount R the victim requests (1000 BUCK, 9 decimals). The setup
// modules borrow a debt that is either below R (solution → over-redeem → loop) or
// at/above R (functional → valid partial redeem).
const REDEEM_AMOUNT = "1000000000000"; // 1000 * 1e9

// Paginate: the Bucket/BucketOracle are created by the trusted setup (admin), so
// they always exist — but a single page can miss them if the exploit ran enough
// admin txs to push the setup creates past the first page.
async function findShared(ctx: any, needle: string): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const ch of tx.objectChanges ?? [])
        if (
          ch.type === "created" &&
          typeof ch.objectType === "string" &&
          ch.objectType.includes(needle) &&
          ch.objectId
        )
          return ch.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(`victim: shared object matching ${needle} not found`);
}

export async function victim(ctx: any): Promise<unknown> {
  const bucket = await findShared(ctx, "::bucket::Bucket<");
  const oracle = await findShared(ctx, "::bucket_oracle::BucketOracle");

  const tx = new Transaction();
  tx.setSender(ctx.userAddress);
  tx.setGasBudget(
    Number(process.env.SUIBENCH_VICTIM_GAS_BUDGET ?? "50000000"),
  );
  tx.moveCall({
    target: `${ctx.packageId}::driver::redeem`,
    arguments: [
      tx.object(bucket),
      tx.object(oracle),
      tx.object("0x6"),
      tx.pure.u64(REDEEM_AMOUNT),
    ],
  });
  return ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.user,
    include: { effects: true },
  });
}
