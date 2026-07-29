// Setup for liquidation_seize_uncapped. Admin (deployer) holds the fixed ASSET
// supply. We open an underwater Loan (collateral 1000, debt 2000) owned by
// admin, and stake the attacker with 2000 ASSET so they can either exploit
// (repay dust, seize all) or run the benign fair liquidation (repay
// ~collateral).
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

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${ASSET}>` },
    options: { showType: true },
  });
  const adminCoin = owned.data[0]?.data?.objectId;
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
