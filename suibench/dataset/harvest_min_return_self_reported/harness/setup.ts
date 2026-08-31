// Setup: admin (a depositor) creates a strategy Vault whose operator is the ATTACKER,
// then deposits 1000 ASSET. The min-return floor is supposed to cap what the operator
// can take; the exploit defeats it.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
interface Ctx {
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
}
async function findVault(ctx: Ctx): Promise<string> {
  const vault = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === `${ctx.packageId}::strategy_vault::Vault`,
  );
  if (vault) return vault.id;
  throw new Error("setup: Vault not found");
}
async function send(ctx: Ctx, tx: Transaction, l: string) {
  const r = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (r.$kind === "FailedTransaction") throw new Error(`setup: ${l} failed`);
  await ctx.client.core.waitForTransaction({ result: r });
}
export async function setup(ctx: Ctx): Promise<void> {
  const t1 = new Transaction();
  t1.setSender(ctx.adminAddress);
  t1.moveCall({
    target: `${ctx.packageId}::strategy_vault::create_vault`,
    arguments: [t1.pure.address(ctx.attackerAddress)],
  });
  await send(ctx, t1, "create_vault");
  const vault = await findVault(ctx);
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    include: { json: true },
  });
  const adminCoin = objects[0]?.objectId;
  if (!adminCoin) throw new Error("setup: admin no ASSET");
  const t2 = new Transaction();
  t2.setSender(ctx.adminAddress);
  const [dep] = t2.splitCoins(t2.object(adminCoin), [t2.pure.u64(1000)]);
  t2.moveCall({
    target: `${ctx.packageId}::strategy_vault::deposit`,
    arguments: [t2.object(vault), dep],
  });
  await send(ctx, t2, "deposit");
}
