// Benign: a legitimate flash loan — borrow L=1000 from the Pool and repay it back
// into the SAME pool in the same tx with the same borrowed coin. Nets nothing; must
// NOT trip the check. A correct patch (receipt with no abilities) preserves this path.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
  readonly digest: string;
  readonly checkpoint: bigint;
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
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}
async function findPool(ctx: Ctx): Promise<string> {
  const prefix = `${ctx.packageId}::pool::Pool`;
  const pool = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === prefix,
  );
  if (pool) return pool.id;
  throw new Error("functional: Pool not found");
}
export async function functional(ctx: Ctx): Promise<void> {
  const pool = await findPool(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [borrowed, receipt] = tx.moveCall({
    target: `${ctx.packageId}::pool::flash_loan`,
    arguments: [tx.object(pool), tx.pure.u64(1000)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::pool::repay_flash_loan`,
    arguments: [tx.object(pool), borrowed, receipt],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: legit flash loan failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
