// Functional (legit-behavior) check for `negative_fee_collateral_inflation` — see
// ../sources/perp.move.
//
// Exploit: settle a NEGATIVE fee of 900 (bounded only by magnitude), pays a legit positive fee then withdraws — nets +50, must NOT trip.
// collateral 100 -> 1000, then withdraw 1000 — draining the vault.
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

async function findEx(ctx: FunctionalContext): Promise<string> {
  const exchange = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === `${ctx.packageId}::perp::Exchange`,
  );
  if (exchange) return exchange.id;
  throw new Error("functional: Exchange not found");
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const ex = await findEx(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const fee = tx.moveCall({
    target: `${ctx.packageId}::perp::make_fee`,
    arguments: [tx.pure.u64(50), tx.pure.bool(false)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::perp::settle_fee`,
    arguments: [tx.object(ex), fee],
  });
  const c = tx.moveCall({
    target: `${ctx.packageId}::perp::withdraw`,
    arguments: [tx.object(ex), tx.pure.u64(50)],
  });
  tx.transferObjects([c], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

