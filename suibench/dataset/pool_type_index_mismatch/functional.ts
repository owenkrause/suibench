// Functional (legit-behavior) check for `pool_type_index_mismatch`.
//
// The legitimate use is to withdraw the asset you actually have a position in,
// with the index and the pool type AGREEING: the attacker withdraws their own
// 500-unit CHEAP position from the cheap pool — `withdraw<CHEAP>(storage,
// cheap_pool, CHEAP_INDEX=0, 500)`. This debits index 0 (their own recorded
// supply) and pays 500 CHEAP out of the CHEAP pool. It gains ZERO VAL, so it
// must NOT trip ../check.ts (whose predicate is a VAL gain). A correct patch
// that binds the index to the pool type leaves this matching-index/matching-
// type path working, so this benign flow keeps succeeding while still gaining
// no VAL.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
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
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

const CHEAP_INDEX = 0;

async function findSharedByPrefix(
  ctx: FunctionalContext,
  fromAddress: string,
  typePrefix: string,
): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: fromAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (
          c.type === "created" &&
          c.objectType?.startsWith(typePrefix) &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(
    `functional: could not find shared object of type ${typePrefix}`,
  );
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const CHEAP = `${ctx.packageId}::cheap::CHEAP`;
  const storageId = await findSharedByPrefix(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::lending::Storage`,
  );
  const cheapPoolId = await findSharedByPrefix(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::lending::Pool<${CHEAP}>`,
  );

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  // Matching index + matching type: withdraw the CHEAP position from the CHEAP pool.
  const out = tx.moveCall({
    target: `${ctx.packageId}::lending::withdraw`,
    typeArguments: [CHEAP],
    arguments: [
      tx.object(storageId),
      tx.object(cheapPoolId),
      tx.pure.u8(CHEAP_INDEX),
      tx.pure.u64(500),
    ],
  });
  tx.transferObjects([out], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: withdraw transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
