// Benign functional path for `unsegregated_protocol_fee` — see ../sources/amm_pool.move.
//
// The attacker adds a tiny 10 ASSET of liquidity and immediately removes it.
// This exercises the same add/remove flow a correct patch preserves, but at a
// trivial size: payout = 10 * 2010 / 1010 = 19, so the net is a negligible +9
// (rounding-scale). A just-in-time LP that provides a tiny slice of liquidity
// nets ~0 and must NOT trip the >= 200 exploit check — only a
// meaningfully-sized redemption skims a meaningful share of the protocol fee.
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
          c.objectType === `${ctx.packageId}::amm_pool::Pool` &&
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
  const [deposit] = tx.splitCoins(tx.object(coin), [tx.pure.u64(10)]);
  tx.moveCall({
    target: `${ctx.packageId}::amm_pool::add_liquidity`,
    arguments: [tx.object(pool), deposit],
  });
  const payout = tx.moveCall({
    target: `${ctx.packageId}::amm_pool::remove_liquidity`,
    arguments: [tx.object(pool), tx.pure.u64(10)],
  });
  tx.transferObjects([payout], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
