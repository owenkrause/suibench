// Setup for liquidation_seize_uncapped. Admin (deployer) holds the fixed ASSET
// supply. We open an underwater Loan (collateral 1000, debt 2000) owned by
// admin, and stake the attacker with 2000 ASSET so they can either exploit
// (repay dust, seize all) or run the benign fair liquidation (repay
// ~collateral).
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
  const [collateral, attackerStake] = tx.splitCoins(tx.object(adminCoin), [
    tx.pure.u64(1000),
    tx.pure.u64(2000),
  ]);
  tx.moveCall({
    target: `${ctx.packageId}::lending::open`,
    arguments: [collateral, tx.pure.u64(2000)],
  });
  tx.transferObjects([attackerStake], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: open/stake tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
