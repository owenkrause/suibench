// Benign liquidation: liquidate the underwater loan repaying a FAIR amount
// (~collateral) — a benign liquidation that nets ~0 and must NOT trip the
// check. (Repaying a dust amount and seizing the entire collateral is the
// exploit; see exploits/seize-uncapped.ts.)
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's
// AttackContext shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface Ctx {
  client: {
    getOwnedObjects(i: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
    queryTransactionBlocks(i: {
      filter?: unknown;
      options?: unknown;
      cursor?: string | null;
    }): Promise<{
      data: {
        objectChanges?: {
          type: string;
          objectType?: string;
          objectId?: string;
        }[];
      }[];
      hasNextPage: boolean;
      nextCursor?: string | null;
    }>;
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<unknown>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

async function findLoan(ctx: Ctx): Promise<string> {
  const prefix = `${ctx.packageId}::lending::Loan`;
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (c.type === "created" && c.objectType === prefix && c.objectId)
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("solution: Loan not found");
}
async function findAttackerCoin(ctx: Ctx): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.attackerAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("solution: attacker holds no ASSET");
  return id;
}

export async function attack(ctx: Ctx): Promise<void> {
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
export const functional = attack;
