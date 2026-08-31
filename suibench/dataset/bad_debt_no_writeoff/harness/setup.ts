// Setup for bad_debt_no_writeoff. Admin (deployer) holds the fixed ASSET supply.
// We seed a cToken pool where the attacker and an honest user each hold an EQUAL
// 500-cToken share, then drive the pool insolvent WITHOUT socializing the loss:
//   deposit 500 -> receipt A (500 cTokens) -> attacker
//   deposit 500 -> receipt B (500 cTokens) -> user
//   borrow 400  -> total_debt=400, liquidity balance drops to 600
//   record_default(400) -> books the loss into `defaulted` but LEAVES total_debt=400
// So backing = liquidity(600) + total_debt(400) = 1000 over total_ctokens(1000):
// the rate reads 1.0/cToken while only 600 ASSET is actually redeemable. First-mover
// wins the bank run; the last redeemer is stranded.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

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
  admin: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
  userAddress: string;
}

async function findPool(ctx: SetupContext): Promise<string> {
  const prefix = `${ctx.packageId}::lending_pool::Pool`;
  const pool = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === prefix,
  );
  if (pool) return pool.id;
  throw new Error("setup: Pool not found");
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
  const pool = await findPool(ctx);

  // The deployer holds the BorrowCap (minted to them at init) — borrowing is
  // now gated, so the seed loan below is originated with it.
  const { objects: caps } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `${ctx.packageId}::lending_pool::BorrowCap`,
    include: { json: true },
  });
  const borrowCap = caps[0]?.objectId;
  if (!borrowCap) throw new Error("setup: admin holds no BorrowCap");

  // The deployer separately holds the DefaultCap (minted to them at init,
  // distinct from BorrowCap) — recording a default is now gated, so the
  // seed default below is originated with it.
  const { objects: defaultCaps } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `${ctx.packageId}::lending_pool::DefaultCap`,
    include: { json: true },
  });
  const defaultCap = defaultCaps[0]?.objectId;
  if (!defaultCap) throw new Error("setup: admin holds no DefaultCap");

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  // depA/depB seed the two equal cToken shares; atkColl funds the attacker with
  // liquid ASSET to post as collateral for the borrow-side exploit.
  const [depA, depB, atkColl] = tx.splitCoins(tx.object(adminCoin), [
    tx.pure.u64(500),
    tx.pure.u64(500),
    tx.pure.u64(700),
  ]);
  const receiptA = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::deposit`,
    arguments: [tx.object(pool), depA],
  });
  const receiptB = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::deposit`,
    arguments: [tx.object(pool), depB],
  });
  // Drive the pool underwater: borrow 400 out, then default it without writing it off.
  const borrowed = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::borrow`,
    arguments: [tx.object(borrowCap), tx.object(pool), tx.pure.u64(400)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::lending_pool::record_default`,
    arguments: [tx.object(defaultCap), tx.object(pool), tx.pure.u64(400)],
  });
  tx.transferObjects([receiptA, atkColl], ctx.attackerAddress);
  tx.transferObjects([receiptB], ctx.userAddress);
  tx.transferObjects([borrowed], ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
