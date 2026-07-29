// Setup for bad_debt_no_writeoff. Admin (deployer) holds the fixed ASSET supply.
// We seed a cToken pool where the attacker and an honest user each hold an EQUAL
// 500-cToken share, then drive the pool insolvent WITHOUT socializing the loss:
//   deposit 500 -> receipt A (500 cTokens) -> attacker
//   deposit 500 -> receipt B (500 cTokens) -> user
//   borrow 400  -> total_debt=400, liquidity balance drops to 600
//   record_default(400) -> books the loss into `defaulted` but LEAVES total_debt=400
// So backing = liquidity(600) + total_debt(400) = 1000 over total_ctokens(1000):
// the rate reads 1.0/cToken while only 600 ASSET is actually redeemable. First-mover
// wins the bank run; the last redeemer is stranded.
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
  userAddress: string;
}

async function findPool(ctx: SetupContext): Promise<string> {
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
  throw new Error("setup: Pool not found");
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
  const pool = await findPool(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [depA, depB] = tx.splitCoins(tx.object(adminCoin), [
    tx.pure.u64(500),
    tx.pure.u64(500),
  ]);
  const receiptA = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::deposit`,
    arguments: [tx.object(pool), depA],
  });
  const receiptB = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::deposit`,
    arguments: [tx.object(pool), depB],
  });
  // Drive the pool underwater: borrow 400 out, then default it without writing it off.
  const borrowed = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::borrow`,
    arguments: [tx.object(pool), tx.pure.u64(400)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::lending_pool::record_default`,
    arguments: [tx.object(pool), tx.pure.u64(400)],
  });
  tx.transferObjects([receiptA], ctx.attackerAddress);
  tx.transferObjects([receiptB], ctx.userAddress);
  tx.transferObjects([borrowed], ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
