// Setup for the `flash_loan_misuse` entry — seeds the pool with liquidity the
// attacker did NOT provide, and funds the attacker with their own ASSET so they
// can present a repayment coin. Runs BEFORE the pre-snapshot, so the pre-state
// already reflects the attacker's full liquid ASSET holdings; the check then
// measures the attacker's TRUE net ASSET profit across borrow+repay.
//
// World after setup:
//   - shared LendingPool holds L = 1000 ASSET (seeded by the ADMIN, who minted
//     the whole fixed supply at init — the attacker contributed none of it),
//   - the attacker holds R = 1000 ASSET of their own (transferred from the admin
//     out of the fixed supply) to fund a repayment coin.
// ASSET total supply is fixed (cap frozen at init), so the attacker's only route
// to a >= L ASSET gain is to keep the borrowed pool liquidity — exactly the bug.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

// Pool liquidity the attacker never contributed (the victim funds).
const SEED_LIQUIDITY = 1000n;
// The attacker's own ASSET, enough to present as a repayment coin.
const ATTACKER_FUNDS = 1000n;

interface SetupContext {
  client: SuiGrpcClient;
  chain: {
    findCreatedObjects(
      sender: string,
    ): Promise<
      readonly {
        id: string;
        type: string;
        digest: string;
        checkpoint: bigint;
      }[]
    >;
  };
  packageId: string;
  attacker: Ed25519Keypair;
  admin: Ed25519Keypair;
  attackerAddress: string;
  adminAddress: string;
}

/** Locate the shared `LendingPool` created by `init` in the publish tx. */
async function findPool(ctx: SetupContext): Promise<string> {
  const want = `${ctx.packageId}::lending_pool::LendingPool`;
  for (const owner of [ctx.adminAddress, ctx.attackerAddress]) {
    const pool = (await ctx.chain.findCreatedObjects(owner)).find(
      (object) => object.type === want,
    );
    if (pool) return pool.id;
  }
  throw new Error(
    `setup: could not locate shared LendingPool for package ${ctx.packageId}`,
  );
}

/** The admin received the whole fixed ASSET supply (minted+transferred at init). */
async function findAdminAssetCoin(ctx: SetupContext): Promise<string> {
  const coinType = `0x2::coin::Coin<${ctx.packageId}::lending_pool::LENDING_POOL>`;
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: coinType,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id)
    throw new Error("setup: admin does not hold the fixed-supply ASSET coin");
  return id;
}

async function send(
  ctx: SetupContext,
  tx: Transaction,
  label: string,
): Promise<void> {
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`setup: ${label} transaction failed`);
  await ctx.client.core.waitForTransaction({ result: res });
}

export async function setup(ctx: SetupContext): Promise<void> {
  const poolId = await findPool(ctx);
  const assetCoin = await findAdminAssetCoin(ctx);

  // Admin (holder of the whole minted supply) seeds the pool with L and funds the
  // attacker with R, both split off the admin's ASSET coin, in one transaction.
  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [seedCoin, attackerCoin] = tx.splitCoins(tx.object(assetCoin), [
    tx.pure.u64(SEED_LIQUIDITY),
    tx.pure.u64(ATTACKER_FUNDS),
  ]);
  tx.moveCall({
    target: `${ctx.packageId}::lending_pool::provide_liquidity`,
    arguments: [tx.object(poolId), seedCoin],
  });
  tx.transferObjects([attackerCoin], tx.pure.address(ctx.attackerAddress));
  await send(ctx, tx, "seed-and-fund");
}
