// Benign liquidation: liquidate the underwater loan repaying a FAIR amount
// (~collateral) — a benign liquidation that nets ~0 and must NOT trip the
// check. (Repaying a dust amount and seizing the entire collateral is the
// exploit; see exploits/seize-uncapped.ts.)
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's
// AttackContext shape — the runner only ever calls `attack`.
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
      }) => Promise<unknown>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
      listOwnedObjects(i: {
        owner: string;
        type?: string;
        include?: { json?: boolean };
      }): Promise<{
        objects: { objectId: string; type: string; json?: unknown }[];
      }>;
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

async function findLoan(ctx: Ctx): Promise<string> {
  const prefix = `${ctx.packageId}::lending::Loan`;
  const loan = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === prefix,
  );
  if (loan) return loan.id;
  throw new Error("solution: Loan not found");
}
async function findAttackerCoin(ctx: Ctx): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("solution: attacker holds no ASSET");
  return id;
}

export async function functional(ctx: Ctx): Promise<void> {
  const loan = await findLoan(ctx);
  const coin = await findAttackerCoin(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [repay] = tx.splitCoins(tx.object(coin), [tx.pure.u64(1000)]);
  const seized = tx.moveCall({
    target: `${ctx.packageId}::lending::liquidate`,
    arguments: [tx.object(loan), repay],
  });
  tx.transferObjects([seized], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}
