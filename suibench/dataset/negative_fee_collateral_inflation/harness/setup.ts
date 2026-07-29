// Setup: admin opens an account and deposits 900 ASSET (vault=900), then funds the
// attacker with 100 ASSET; the attacker opens an account and deposits 100 (vault=1000,
// attacker collateral=100). The 900 of admin collateral is what the exploit drains.
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
  attacker: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}
async function findEx(ctx: Ctx): Promise<string> {
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
  throw new Error("setup: Exchange not found");
}
async function coinOf(ctx: Ctx, owner: string): Promise<string> {
  const o = await ctx.client.getOwnedObjects({
    owner,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>` },
    options: { showType: true },
  });
  const id = o.data[0]?.data?.objectId;
  if (!id) throw new Error(`setup: ${owner} no ASSET`);
  return id;
}
async function send(ctx: Ctx, tx: Transaction, signer: unknown, l: string) {
  const r = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer,
    include: { effects: true },
  });
  if (r.$kind === "FailedTransaction") throw new Error(`setup: ${l} failed`);
  await ctx.client.core.waitForTransaction({ result: r });
}
export async function setup(ctx: Ctx): Promise<void> {
  const ex = await findEx(ctx);
  const adminCoin = await coinOf(ctx, ctx.adminAddress);
  const t1 = new Transaction();
  t1.setSender(ctx.adminAddress);
  const [dep, att] = t1.splitCoins(t1.object(adminCoin), [
    t1.pure.u64(900),
    t1.pure.u64(100),
  ]);
  t1.moveCall({
    target: `${ctx.packageId}::perp::open_account`,
    arguments: [t1.object(ex)],
  });
  t1.moveCall({
    target: `${ctx.packageId}::perp::deposit`,
    arguments: [t1.object(ex), dep],
  });
  t1.transferObjects([att], ctx.attackerAddress);
  await send(ctx, t1, ctx.admin, "admin deposit + fund");
  const attCoin = await coinOf(ctx, ctx.attackerAddress);
  const t2 = new Transaction();
  t2.setSender(ctx.attackerAddress);
  t2.moveCall({
    target: `${ctx.packageId}::perp::open_account`,
    arguments: [t2.object(ex)],
  });
  t2.moveCall({
    target: `${ctx.packageId}::perp::deposit`,
    arguments: [t2.object(ex), t2.object(attCoin)],
  });
  await send(ctx, t2, ctx.attacker, "attacker deposit");
}
