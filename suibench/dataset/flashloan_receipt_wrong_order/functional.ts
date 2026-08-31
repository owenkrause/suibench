// Benign: a legitimate flash loan — borrow from V and repay back into V (the correct
// order). Nets nothing; must NOT trip the check. A correct patch preserves this path.
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
async function findOrder(ctx: Ctx, from: string): Promise<string> {
  const order = (await ctx.chain.findCreatedObjects(from)).find(
    (object) => object.type === `${ctx.packageId}::limit_order::LimitOrder`,
  );
  if (order) return order.id;
  throw new Error(`functional: LimitOrder from ${from} not found`);
}
export async function functional(ctx: Ctx): Promise<void> {
  const V = await findOrder(ctx, ctx.adminAddress);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [borrowed, receipt] = tx.moveCall({
    target: `${ctx.packageId}::limit_order::flash_loan`,
    arguments: [tx.object(V), tx.pure.u64(1000)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::limit_order::repay_flash_loan`,
    arguments: [tx.object(V), borrowed, receipt],
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
