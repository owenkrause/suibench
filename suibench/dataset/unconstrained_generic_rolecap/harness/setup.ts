// Setup for unconstrained_generic_rolecap. Admin (deployer) holds the fixed ASSET
// supply and the genuine RoleCap<AdminRole> minted in init. The shared Treasury is
// created empty by init; here the admin funds it with 1000 ASSET via `deposit` so
// there is real value for an escalated attacker to drain (and for the legit admin
// to withdraw benignly in the functional run).
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

async function findTreasury(ctx: SetupContext): Promise<string> {
  const prefix = `${ctx.packageId}::access_control::Treasury`;
  const created = await ctx.chain.findCreatedObjects(ctx.adminAddress);
  for (const object of created) {
    if (object.type === prefix) return object.id;
  }
  throw new Error("setup: Treasury not found");
}

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ASSET}>`,
  });
  const adminCoin = owned.objects[0]?.objectId;
  if (!adminCoin) throw new Error("setup: admin holds no ASSET");

  const treasury = await findTreasury(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [fund] = tx.splitCoins(tx.object(adminCoin), [tx.pure.u64(1000)]);
  tx.moveCall({
    target: `${ctx.packageId}::access_control::deposit`,
    arguments: [tx.object(treasury), fund],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: deposit tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
