// Setup: admin (a depositor) creates a strategy Vault whose operator is the ATTACKER,
// then deposits 1000 ASSET. The min-return floor is supposed to cap what the operator
// can take; the exploit defeats it.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
interface Ctx {
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
async function findVault(ctx: Ctx): Promise<string> {
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
          c.objectType === `${ctx.packageId}::strategy_vault::Vault` &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("setup: Vault not found");
}
async function send(ctx: Ctx, tx: Transaction, l: string) {
  const r = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (r.$kind === "FailedTransaction") throw new Error(`setup: ${l} failed`);
  await ctx.client.core.waitForTransaction({ result: r });
}
export async function setup(ctx: Ctx): Promise<void> {
  const t1 = new Transaction();
  t1.setSender(ctx.adminAddress);
  t1.moveCall({
    target: `${ctx.packageId}::strategy_vault::create_vault`,
    arguments: [t1.pure.address(ctx.attackerAddress)],
  });
  await send(ctx, t1, "create_vault");
  const vault = await findVault(ctx);
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>` },
    options: { showType: true },
  });
  const adminCoin = owned.data[0]?.data?.objectId;
  if (!adminCoin) throw new Error("setup: admin no ASSET");
  const t2 = new Transaction();
  t2.setSender(ctx.adminAddress);
  const [dep] = t2.splitCoins(t2.object(adminCoin), [t2.pure.u64(1000)]);
  t2.moveCall({
    target: `${ctx.packageId}::strategy_vault::deposit`,
    arguments: [t2.object(vault), dep],
  });
  await send(ctx, t2, "deposit");
}
