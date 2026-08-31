// Setup: admin opens an account and deposits 900 ASSET (vault=900), then funds the
// attacker with 100 ASSET; the attacker opens an account and deposits 100 (vault=1000,
// attacker collateral=100). The 900 of admin collateral is what the exploit drains.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface Ctx {
  client: SuiGrpcClient & {
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  admin: Ed25519Keypair;
  attacker: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}
async function findEx(ctx: Ctx): Promise<string> {
  const exchange = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === `${ctx.packageId}::perp::Exchange`,
  );
  if (exchange) return exchange.id;
  throw new Error("setup: Exchange not found");
}
async function coinOf(ctx: Ctx, owner: string): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
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
