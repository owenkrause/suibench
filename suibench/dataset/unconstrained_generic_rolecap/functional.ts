// Benign functional flow: the LEGITIMATE admin (the deployer, who holds the genuine
// RoleCap<AdminRole> minted to them in init) withdraws from the Treasury with their
// real admin cap and keeps the funds themselves. This is the intended, authorized
// use of `withdraw` — no escalation, no attacker involvement — so the attacker's
// ASSET balance is unchanged and ./check.ts must NOT trip.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Signer } from "@mysten/sui/cryptography";
interface NativeChain {
  findCreatedObjects(sender: string): Promise<
    readonly { id: string; type: string; digest: string; checkpoint: bigint }[]
  >;
}


interface FunctionalContext {
  client: SuiGrpcClient;
  chain: NativeChain;
  packageId: string;
  admin: Signer;
  attacker: Signer;
  attackerAddress: string;
  adminAddress: string;
}

async function findTreasury(ctx: FunctionalContext): Promise<string> {
  const prefix = `${ctx.packageId}::access_control::Treasury`;
  const created = await ctx.chain.findCreatedObjects(ctx.adminAddress);
  for (const object of created) {
    if (object.type === prefix) return object.id;
  }
  throw new Error("functional: Treasury not found");
}

async function findAdminCap(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `${ctx.packageId}::access_control::RoleCap<${ctx.packageId}::access_control::AdminRole>`,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error("functional: admin holds no RoleCap<AdminRole>");
  return id;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const treasury = await findTreasury(ctx);
  const adminCap = await findAdminCap(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const coin = tx.moveCall({
    target: `${ctx.packageId}::access_control::withdraw`,
    arguments: [tx.object(adminCap), tx.object(treasury), tx.pure.u64(1000)],
  });
  tx.transferObjects([coin], ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}
