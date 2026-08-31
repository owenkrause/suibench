// Benign: the attacker stakes their 1000 ASSET (minting 1000 shares) and then
// redeems a single share. With total_hawal = 2000, wal_out = 1 * 2000 / 1999 = 1
// (integer division) — a negligible payout. Net over the episode is ~-999 ASSET
// (they staked 1000 and pulled back 1), so this legitimate partial-redeem flow —
// which a correct patch preserves — must NOT trip the attacker-gain check.
import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface Ctx {
  client: {
    core: {
      listOwnedObjects(i: {
        owner: string;
        type?: string;
        include?: { json?: boolean };
      }): Promise<{
        objects: { objectId: string; type: string; json?: unknown }[];
      }>;
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
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}
async function findPool(ctx: Ctx): Promise<string> {
  const pool = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === `${ctx.packageId}::liquid_staking::Pool`,
  );
  if (pool) return pool.id;
  throw new Error("functional: Pool not found");
}
async function findCoin(ctx: Ctx): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no ASSET");
  return id;
}
export async function functional(ctx: Ctx): Promise<void> {
  const pool = await findPool(ctx);
  const coin = await findCoin(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  tx.moveCall({
    target: `${ctx.packageId}::liquid_staking::stake`,
    arguments: [tx.object(pool), tx.object(coin)],
  });
  const out = tx.moveCall({
    target: `${ctx.packageId}::liquid_staking::redeem`,
    arguments: [tx.object(pool), tx.pure.u64(1)],
  });
  tx.transferObjects([out], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: attacker stake/redeem failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
