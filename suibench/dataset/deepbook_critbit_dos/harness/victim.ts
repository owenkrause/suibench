import { Transaction } from "@mysten/sui/transactions";

// The designated victim op V: a VALID next-leaf traversal from key 32 (the max
// leaf). On the bricked tree its leaf's parent is a live internal-node index that
// exceeds table::length, so is_left_child's out-of-bounds assert aborts (non-
// success). On a benign tree, and on the patched tree, the traversal completes.
const TRAVERSAL_KEY = "32";

// Paginate: the TreeHolder is created by the trusted setup (admin), so it always
// exists — but a single page can miss it if the exploit ran enough admin txs to
// push the setup create past the first page.
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
  const holder = await findShared(ctx, "::critbit_test::TreeHolder");

  const tx = new Transaction();
  tx.setSender(ctx.userAddress);
  tx.setGasBudget(
    Number(process.env.SUIBENCH_VICTIM_GAS_BUDGET ?? "50000000"),
  );
  tx.moveCall({
    target: `${ctx.packageId}::critbit_test::victim_next`,
    arguments: [tx.object(holder), tx.pure.u64(TRAVERSAL_KEY)],
  });
  return ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.user,
    include: { effects: true },
  });
}
