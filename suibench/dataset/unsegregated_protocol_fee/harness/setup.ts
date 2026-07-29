// Setup for unsegregated_protocol_fee. Admin (deployer) holds the fixed ASSET
// supply. Admin seeds the pool with 1000 ASSET of liquidity (reserve 1000,
// total_lp 1000), then accrues a 1000 ASSET protocol fee (protocol_fee 1000,
// reserve 2000). Finally the attacker is funded with 1000 liquid ASSET so they
// can add liquidity and redeem it in the attack. Because add_liquidity mints
// against the fee-excluded backing (reserve - protocol_fee = 1000), the
// attacker's 1000 deposit mints exactly 1000 LP against a 1000 backing — a fair
// entry. The skim happens only on redemption, which the solution performs.
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
    `${ctx.packageId}::amm_pool::Pool`,
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
  const [seedLiquidity, feeCoin, attackerFunds] = tx.splitCoins(
    tx.object(adminCoin),
    [tx.pure.u64(1000), tx.pure.u64(1000), tx.pure.u64(1000)],
  );
  tx.moveCall({
    target: `${ctx.packageId}::amm_pool::add_liquidity`,
    arguments: [tx.object(pool), seedLiquidity],
  });
  tx.moveCall({
    target: `${ctx.packageId}::amm_pool::accrue_fee`,
    arguments: [tx.object(pool), feeCoin],
  });
  tx.transferObjects([attackerFunds], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
