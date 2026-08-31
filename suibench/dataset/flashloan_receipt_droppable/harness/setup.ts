// Setup for flashloan_receipt_droppable. Admin (deployer) holds the fixed ASSET
// supply. Admin creates the shared Pool seeded with L = 1000 ASSET liquidity. The
// attacker is NOT funded with any pool liquidity — any ASSET they end up holding is
// drained from the pool (the seeded liquidity), so the check measures true theft.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiGrpcClient;
  packageId: string;
  admin: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ASSET}>`,
    include: { json: true },
  });
  const adminCoin = objects[0]?.objectId;
  if (!adminCoin) throw new Error("setup: admin holds no ASSET");

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [liquidity] = tx.splitCoins(tx.object(adminCoin), [tx.pure.u64(1000)]);
  tx.moveCall({
    target: `${ctx.packageId}::pool::create_pool`,
    arguments: [liquidity],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: create_pool tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
