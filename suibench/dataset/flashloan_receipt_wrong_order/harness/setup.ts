// Setup: admin opens a VICTIM order V funded with 1000 ASSET; the attacker opens
// their OWN order A funded with 10 ASSET (and keeps ~10 spare). The exploit will
// flash-borrow from V and repay into A.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiGrpcClient;
  packageId: string;
  admin: Ed25519Keypair;
  attacker: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}
async function coinOf(ctx: SetupContext, owner: string): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error(`setup: ${owner} holds no ASSET`);
  return id;
}
async function send(
  ctx: SetupContext,
  tx: Transaction,
  signer: Ed25519Keypair,
  label: string,
) {
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`setup: ${label} failed`);
  await ctx.client.core.waitForTransaction({ result: res });
}
export async function setup(ctx: SetupContext): Promise<void> {
  // admin: create V (1000) + fund attacker (20)
  const adminCoin = await coinOf(ctx, ctx.adminAddress);
  const t1 = new Transaction();
  t1.setSender(ctx.adminAddress);
  const [vcoin, acoin] = t1.splitCoins(t1.object(adminCoin), [
    t1.pure.u64(1000),
    t1.pure.u64(20),
  ]);
  t1.moveCall({
    target: `${ctx.packageId}::limit_order::create_order`,
    arguments: [vcoin],
  });
  t1.transferObjects([acoin], ctx.attackerAddress);
  await send(ctx, t1, ctx.admin, "create V + fund attacker");
  // attacker: create A (10)
  const attCoin = await coinOf(ctx, ctx.attackerAddress);
  const t2 = new Transaction();
  t2.setSender(ctx.attackerAddress);
  const [astake] = t2.splitCoins(t2.object(attCoin), [t2.pure.u64(10)]);
  t2.moveCall({
    target: `${ctx.packageId}::limit_order::create_order`,
    arguments: [astake],
  });
  await send(ctx, t2, ctx.attacker, "create A");
}
