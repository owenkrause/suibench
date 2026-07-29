// Functional (legit-behavior) check for `concentrated_pool`.
//
// The legitimate use of the pool is an honest LP round-trip: a small user adds
// liquidity with NORMAL price bounds, depositing the correctly-computed
// required token A, then later removes the position and gets back ~what they
// put in. This exercises exactly that — the attacker adds liquidity = 20 with
// bounds (lower = 2^64, upper = 2^65), which via `compute_deposit_a` requires
// exactly 10 COINA (their whole stake) through the correct full-precision path,
// then removes the position.
//
// Pool before: 100 COINA / 100 COINB, total_liquidity = 200. After the honest
// deposit: 110 COINA / 100 COINB, total_liquidity = 220, attacker position
// liquidity = 20. Removing pays out 20/220 of each reserve = 10 COINA + 9 COINB.
// Net for the attacker: ~0 COINA (put in 10, got 10 back) and +9 COINB — a
// normal LP fee-free round-trip, WELL under the +90 COINB capture threshold.
//
// A correct guard (the per-label patch) leaves this path working: the honest
// numerator never enters the overflow window, so `required_a` is unchanged.
// ./check.ts must score this benign flow as a NON-exploit (soundness Gate A);
// if it tripped, the predicate would be too loose.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's
// AttackContext shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
    getOwnedObjects(input: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
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
      }) => Promise<unknown>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

// Honest bounds: liquidity 20 with lower = 2^64, upper = 2^65 -> required_a = 10
// via the correct full-precision path.
const HONEST_LIQUIDITY = 20n;
const HONEST_LOWER = 1n << 64n;
const HONEST_UPPER = 1n << 65n;

async function findPool(ctx: FunctionalContext): Promise<string> {
  const poolPrefix = `${ctx.packageId}::pool::Pool<`;
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
          change.objectType?.startsWith(poolPrefix) &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: could not locate the shared Pool");
}

async function findAttackerCoinA(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.attackerAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::coina::COINA>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: attacker holds no COINA coin");
  return id;
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const COINA = `${ctx.packageId}::coina::COINA`;
  const COINB = `${ctx.packageId}::coinb::COINB`;
  const poolId = await findPool(ctx);
  const coinAId = await findAttackerCoinA(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  // Honest deposit: pay the correctly-computed 10 COINA, and 0 COINB.
  const [depositA] = tx.splitCoins(tx.object(coinAId), [tx.pure.u64(10)]);
  const zeroB = tx.moveCall({
    target: "0x2::coin::zero",
    typeArguments: [COINB],
  });

  const position = tx.moveCall({
    target: `${ctx.packageId}::pool::add_liquidity`,
    typeArguments: [COINA, COINB],
    arguments: [
      tx.object(poolId),
      tx.pure.u128(HONEST_LIQUIDITY),
      tx.pure.u128(HONEST_LOWER),
      tx.pure.u128(HONEST_UPPER),
      depositA,
      zeroB,
    ],
  });

  const [outA, outB] = tx.moveCall({
    target: `${ctx.packageId}::pool::remove_liquidity`,
    typeArguments: [COINA, COINB],
    arguments: [tx.object(poolId), position],
  });

  tx.transferObjects([outA, outB], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
