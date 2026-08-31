// Setup for withdraw_penalty_not_withheld. Admin (deployer) holds the fixed ASSET
// supply and owns the Pool created at publish (init shares an empty Pool). We seed
// the Pool with 100000 ASSET of real capital (standing in for other LPs' deposits),
// and stake the attacker with 50000 liquid ASSET. The attacker's OWN deposit is done
// inside the attack scripts (not here), so the pre-state snapshot captures the
// attacker's full 50000 liquid balance and the check measures true NET profit.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
interface NativeChain {
  findCreatedObjects(sender: string): Promise<
    readonly { id: string; type: string; digest: string; checkpoint: bigint }[]
  >;
}


interface SetupContext {
  client: SuiGrpcClient;
  chain: NativeChain;
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
  const created = await ctx.chain.findCreatedObjects(from);
  for (const object of created) {
    if (object.type === type) return object.id;
  }
  throw new Error(`setup: ${type} not found`);
}

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const pool = await findShared(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::liquidity_provider::Pool`,
  );
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ASSET}>`,
  });
  const adminCoin = owned.objects[0]?.objectId;
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
