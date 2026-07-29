// Setup for withdraw_penalty_not_withheld. Admin (deployer) holds the fixed ASSET
// supply and owns the Pool created at publish (init shares an empty Pool). We seed
// the Pool with 100000 ASSET of real capital (standing in for other LPs' deposits),
// and stake the attacker with 50000 liquid ASSET. The attacker's OWN deposit is done
// inside the attack scripts (not here), so the pre-state snapshot captures the
// attacker's full 50000 liquid balance and the check measures true NET profit.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiJsonRpcClient & {
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
  admin: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}

async function findShared(
  ctx: SetupContext,
  from: string,
  type: string,
): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: from },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (c.type === "created" && c.objectType === type && c.objectId)
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(`setup: ${type} not found`);
}

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const pool = await findShared(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::liquidity_provider::Pool`,
  );
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${ASSET}>` },
    options: { showType: true },
  });
  const adminCoin = owned.data[0]?.data?.objectId;
  if (!adminCoin) throw new Error("setup: admin holds no ASSET");

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [poolCapital, attackerStake] = tx.splitCoins(tx.object(adminCoin), [
    tx.pure.u64(100000),
    tx.pure.u64(50000),
  ]);
  tx.moveCall({
    target: `${ctx.packageId}::liquidity_provider::deposit`,
    arguments: [tx.object(pool), poolCapital],
  });
  tx.transferObjects([attackerStake], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed/stake tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
