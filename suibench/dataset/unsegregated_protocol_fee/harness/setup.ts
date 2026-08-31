// Setup for unsegregated_protocol_fee. Admin (deployer) holds the fixed ASSET
// supply. Admin seeds the pool with 1000 ASSET of liquidity (reserve 1000,
// total_lp 1000), then accrues a 1000 ASSET protocol fee (protocol_fee 1000,
// reserve 2000). Finally the attacker is funded with 1000 liquid ASSET so they
// can add liquidity and redeem it in the attack. Because add_liquidity mints
// against the fee-excluded backing (reserve - protocol_fee = 1000), the
// attacker's 1000 deposit mints exactly 1000 LP against a 1000 backing — a fair
// entry. The skim happens only on redemption, which the solution performs.
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
    `${ctx.packageId}::amm_pool::Pool`,
  );
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ASSET}>`,
  });
  const adminCoin = owned.objects[0]?.objectId;
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
