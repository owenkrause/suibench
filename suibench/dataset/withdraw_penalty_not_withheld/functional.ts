// Benign functional path for `withdraw_penalty_not_withheld` — see
// ../sources/liquidity_provider.move.
//
// The legitimate LP flow: deposit 50000, then withdraw exactly the 50000
// principal. A fair withdrawal takes back only what was deposited — no skim
// of the pool's other capital — so the attacker's net over their own stake is
// 0 (buggy contract) or -2500 (correct contract, penalty withheld). Either
// way this is well under the exploit threshold and must NOT trip the check.
//
// This file exports `attack(ctx)` — the same AttackContext shape the
// confirmer's in-container runner (src/confirmer/runner.ts) invokes — so the
// existing container plumbing runs it unchanged. `functional` is exported as
// an alias for readability at the call site; the runner only ever calls
// `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
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

async function findPool(ctx: FunctionalContext): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (
          c.type === "created" &&
          c.objectType === `${ctx.packageId}::liquidity_provider::Pool` &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: Pool not found");
}
async function findCoin(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.attackerAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: attacker holds no ASSET");
  return id;
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const pool = await findPool(ctx);
  const coin = await findCoin(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [stake] = tx.splitCoins(tx.object(coin), [tx.pure.u64(50000)]);
  tx.moveCall({
    target: `${ctx.packageId}::liquidity_provider::deposit`,
    arguments: [tx.object(pool), stake],
  });
  const out = tx.moveCall({
    target: `${ctx.packageId}::liquidity_provider::withdraw`,
    arguments: [tx.object(pool), tx.pure.u64(50000)],
  });
  tx.transferObjects([out], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
