// Setup: admin stakes 1000 ASSET (total_wal=1000, total_hawal=1000, admin owns
// 1000 shares) and funds the attacker with 1000 ASSET. The attacker's own stake
// happens inside the attack script, so the pre-attack snapshot captures the
// attacker holding their full 1000 ASSET — letting the check measure net profit
// (redeem proceeds minus the stake) rather than gross redeem output.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface SetupContext {
  client: SuiGrpcClient & {
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
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
  const object = (await ctx.chain.findCreatedObjects(from)).find(
    (created) => created.type === type,
  );
  if (object) return object.id;
  throw new Error(`setup: ${type} not found`);
}

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const pool = await findShared(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::liquid_staking::Pool`,
  );
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ASSET}>`,
    include: { json: true },
  });
  const adminCoin = objects[0]?.objectId;
  if (!adminCoin) throw new Error("setup: admin holds no ASSET");

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [adminStake, attackerFund] = tx.splitCoins(tx.object(adminCoin), [
    tx.pure.u64(1000),
    tx.pure.u64(1000),
  ]);
  tx.moveCall({
    target: `${ctx.packageId}::liquid_staking::stake`,
    arguments: [tx.object(pool), adminStake],
  });
  tx.transferObjects([attackerFund], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: admin stake / fund tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
