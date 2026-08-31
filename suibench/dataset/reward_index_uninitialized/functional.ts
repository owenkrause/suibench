// Functional (legit-behavior) check for `reward_index_uninitialized` — see
// ../sources/spool.move.
//
// Benign: the legitimate long-term staker (admin, who staked before the reward accrued)
// claims their earned rewards. This exercises the claim path a correct patch preserves
// and does not create the shared-Spool state transition required by the
// operation-specific checker.
import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface Ctx {
  client: {
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
  admin: unknown;
  adminAddress: string;
}

async function findSpool(ctx: Ctx): Promise<string> {
  const spool = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === `${ctx.packageId}::spool::Spool`,
  );
  if (spool) return spool.id;
  throw new Error("functional: Spool not found");
}

export async function functional(ctx: Ctx): Promise<void> {
  const spool = await findSpool(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const reward = tx.moveCall({
    target: `${ctx.packageId}::spool::claim`,
    arguments: [tx.object(spool)],
  });
  tx.transferObjects([reward], ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: admin claim failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
