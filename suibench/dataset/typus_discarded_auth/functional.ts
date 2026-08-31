import { Transaction } from "@mysten/sui/transactions";
import { SUI_CLOCK_OBJECT_ID } from "@mysten/sui/utils";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Signer } from "@mysten/sui/cryptography";
interface NativeChain {
  findCreatedObjects(sender: string): Promise<
    readonly { id: string; type: string; digest: string; checkpoint: bigint }[]
  >;
}


const LEGIT_PRICE = 42n;
const LEGIT_TWAP = 42n;

interface FunctionalContext {
  client: SuiGrpcClient;
  chain: NativeChain;
  packageId: string;
  admin: Signer;
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
}

async function findShared(
  ctx: FunctionalContext,
  expectedType: string,
): Promise<string> {
  for (const owner of [
    ctx.adminAddress,
    ctx.attackerAddress,
    ctx.userAddress,
  ]) {
    const created = await ctx.chain.findCreatedObjects(owner);
    for (const object of created) {
      if (object.type === expectedType) return object.id;
    }
  }
  throw new Error(`functional: could not locate shared ${expectedType}`);
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const oracleId = await findShared(
    ctx,
    `${ctx.packageId}::oracle::Oracle`,
  );
  const authorityId = await findShared(
    ctx,
    `${ctx.packageId}::oracle::UpdateAuthority`,
  );

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  tx.moveCall({
    target: `${ctx.packageId}::oracle::update_v2`,
    arguments: [
      tx.object(oracleId),
      tx.object(authorityId),
      tx.pure.u64(LEGIT_PRICE),
      tx.pure.u64(LEGIT_TWAP),
      tx.object(SUI_CLOCK_OBJECT_ID),
    ],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction") {
    throw new Error("functional: authorized admin update_v2 failed");
  }
  await ctx.client.core.waitForTransaction({ result: res });
}
