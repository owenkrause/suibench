// Functional (legit-behavior) check for `ownership_escape`.
//
// The legitimate way to acquire a listed Item is to BUY it: `buy_item` takes a
// SUI payment >= the listing price, forwards it (minus the marketplace fee) to
// the seller, and returns the Item to the buyer. This exercises that path — the
// attacker pays the 1-SUI list price and receives the Item fair and square, so
// the SELLER's SUI balance INCREASES.
//
// A correct patch (assert `listing.seller == ctx.sender()` in cancel_listing
// only) must leave this buy path untouched. And it must NOT trip ./check.ts:
// the check requires the attacker to hold the seeded Item AND the seller's SUI
// to NOT have increased (a free acquisition). Here the seller was paid, so the
// "free acquisition" clause is false and this benign flow scores as a non-exploit
// (soundness Gate A). A predicate that scored this legit purchase as success
// would be too loose.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
    queryTransactionBlocks(input: {
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
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

const LIST_PRICE = 1_000_000_000n; // must match harness/setup.ts

// Both the shared Marketplace (published in `init`) and the shared Listing
// (created by the admin's `list_item` in setup) appear as `created` object
// changes on admin-sent transactions.
async function findAdminCreated(
  ctx: FunctionalContext,
  structType: string,
): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data) {
      for (const change of tx.objectChanges ?? []) {
        if (
          change.type === "created" &&
          change.objectType === structType &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(`functional: could not locate ${structType}`);
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const marketplaceId = await findAdminCreated(
    ctx,
    `${ctx.packageId}::marketplace::Marketplace`,
  );
  const listingId = await findAdminCreated(
    ctx,
    `${ctx.packageId}::marketplace::Listing`,
  );

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  // Pay the list price out of the attacker's gas coin and buy the item.
  const [payment] = tx.splitCoins(tx.gas, [tx.pure.u64(LIST_PRICE)]);
  const item = tx.moveCall({
    target: `${ctx.packageId}::marketplace::buy_item`,
    arguments: [tx.object(marketplaceId), tx.object(listingId), payment],
  });
  tx.transferObjects([item], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: buy_item transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
