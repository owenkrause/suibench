// Setup for order_overfill_original_quantity. Admin (deployer) holds the fixed ASSET
// supply and is the MAKER. We open a Manager funded with 100_000 ASSET, place an order
// of quantity 10_000, and have the MAKER (admin) partially fill it once (take_qty 9_000)
// so `order.filled` becomes 9_000 and only 1_000 remains. The partial fill is done by
// admin — not the attacker — so the attacker's pre-snapshot ASSET balance is 0 and the
// check measures only what the taker later pulls out. The attacker (taker) is left with
// no ASSET; both the benign fair fill and the over-fill happen in the attack scripts.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiJsonRpcClient & {
    getOwnedObjects(input: {
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
  admin: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}

async function findCreated(
  ctx: SetupContext,
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
  throw new Error(`setup: object of type ${objectType} not found`);
}

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${ASSET}>` },
    options: { showType: true },
  });
  const adminCoin = owned.data[0]?.data?.objectId;
  if (!adminCoin) throw new Error("setup: admin holds no ASSET");

  // Open the maker's Manager funded with 100_000 base, and place an order of quantity 10_000.
  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [managerBase] = tx.splitCoins(tx.object(adminCoin), [
    tx.pure.u64(100000),
  ]);
  tx.moveCall({
    target: `${ctx.packageId}::orderbook::open_manager`,
    arguments: [managerBase],
  });
  tx.moveCall({
    target: `${ctx.packageId}::orderbook::place_order`,
    arguments: [tx.pure.u64(10000), tx.pure.u64(1)],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: open_manager/place_order tx failed");
  await ctx.client.core.waitForTransaction({ result: res });

  const manager = await findCreated(
    ctx,
    `${ctx.packageId}::orderbook::Manager`,
  );
  const order = await findCreated(ctx, `${ctx.packageId}::orderbook::Order`);

  // Maker (admin) partially fills its own order once so filled = 9_000, remaining = 1_000.
  // Base returned goes back to admin (who already holds the whole supply), leaving the
  // attacker with zero ASSET at the pre-snapshot.
  const fillTx = new Transaction();
  fillTx.setSender(ctx.adminAddress);
  const [base] = fillTx.moveCall({
    target: `${ctx.packageId}::orderbook::take`,
    arguments: [
      fillTx.object(order),
      fillTx.object(manager),
      fillTx.pure.u64(9000),
    ],
  });
  fillTx.transferObjects([base], ctx.adminAddress);
  const res2 = await ctx.client.core.signAndExecuteTransaction({
    transaction: fillTx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res2.$kind === "FailedTransaction")
    throw new Error("setup: partial fill tx failed");
  await ctx.client.core.waitForTransaction({ result: res2 });
}
