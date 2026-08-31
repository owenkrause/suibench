// Functional (legit-behavior) check for `order_overfill_original_quantity` — see
// ../sources/orderbook.move.
//
// Benign taker: the maker's order (quantity 10_000) has already been filled for 9_000, so
// only 1_000 legitimately remains. A fair taker fills exactly the remaining 1_000 and
// receives 1_000 base — a legitimate trade that must NOT trip the check. The over-fill
// (matching the full 10_000 against a nearly-exhausted order) is what the check flags; a
// fair remaining fill nets only 1_000, well under the threshold.
import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface FunctionalContext {
  client: {
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<unknown>;
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

async function findCreated(
  ctx: FunctionalContext,
  objectType: string,
): Promise<string> {
  const object = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (created) => created.type === objectType,
  );
  if (object) return object.id;
  throw new Error(`functional: object of type ${objectType} not found`);
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const order = await findCreated(ctx, `${ctx.packageId}::orderbook::Order`);
  const manager = await findCreated(
    ctx,
    `${ctx.packageId}::orderbook::Manager`,
  );
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [base] = tx.moveCall({
    target: `${ctx.packageId}::orderbook::take`,
    arguments: [tx.object(order), tx.object(manager), tx.pure.u64(1000)],
  });
  tx.transferObjects([base], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

