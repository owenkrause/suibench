// Setup: admin stakes 1000 ASSET, then adds a 10000 ASSET reward (reward_index -> 10),
// then transfers the attacker a 100 ASSET coin. The attacker chooses its 55 ASSET
// stake in the committed exploit, after the pool has accrued rewards belonging to
// the admin's earlier stake.
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
  const spool = await findShared(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::spool::Spool`,
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
  const [stakeCoin, rewardCoin, attackerStake] = tx.splitCoins(
    tx.object(adminCoin),
    [tx.pure.u64(1000), tx.pure.u64(10000), tx.pure.u64(100)],
  );
  tx.moveCall({
    target: `${ctx.packageId}::spool::stake`,
    arguments: [tx.object(spool), stakeCoin],
  });
  tx.moveCall({
    target: `${ctx.packageId}::spool::add_reward`,
    arguments: [tx.object(spool), rewardCoin],
  });
  tx.transferObjects([attackerStake], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
