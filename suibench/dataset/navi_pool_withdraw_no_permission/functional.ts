// Functional (legit-behavior) check for `navi_pool_withdraw_no_permission`.
//
// The legitimate use of `withdraw` is the pool's OPERATOR pulling funds back out.
// This exercises exactly that: the ADMIN (who created the pool in
// ./harness/setup.ts and is therefore the operator) locates the Pool and calls
// `withdraw(pool, 1000)`, keeping the coin. A correct patch — which gates
// `withdraw` on `sender == pool.operator` — must keep this path working.
//
// It must NOT trip ./check.ts, which scores the ATTACKER's TOKEN gain. Here the
// operator is the admin, not the attacker, so the attacker gains nothing and the
// predicate is false. If check.ts scored this benign operator withdrawal as a
// success, the predicate would be unsound (soundness Gate A).
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`. Signs with the ADMIN keypair.
import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface FunctionalContext {
  client: {
    core: {
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  admin: unknown;
  adminAddress: string;
  attackerAddress: string;
}

async function findPool(ctx: FunctionalContext): Promise<string> {
  const poolType = `${ctx.packageId}::pool::Pool`;
  const pool = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === poolType,
  );
  if (pool) return pool.id;
  throw new Error("functional: could not locate the shared Pool");
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const poolId = await findPool(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const withdrawn = tx.moveCall({
    target: `${ctx.packageId}::pool::withdraw`,
    arguments: [tx.object(poolId), tx.pure.u64(1000)],
  });
  tx.transferObjects([withdrawn], ctx.adminAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: operator withdraw failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

