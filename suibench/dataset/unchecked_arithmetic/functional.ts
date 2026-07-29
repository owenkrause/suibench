// Functional (legit-behavior) check for `unchecked_arithmetic`.
//
// The legitimate flow is two normal-sized deposits into the reward pool. Here the
// attacker (first depositor) deposits their liquid ASSET and the VICTIM then
// deposits their D = 100,000 ASSET — a normal amount, with NO donation inflating
// the pool. Under correct-sized deposits `deposit` mints proportional, NONZERO
// shares to both, and the attacker then withdraws roughly what they put in
// (net ~0). Because there is no share-inflation donation:
//   - the victim receives NONZERO shares (clause 2 of ./check.ts fails), and
//   - the attacker nets ~0 ASSET (clause 1 fails).
// So this benign path must NOT trip ./check.ts. It exercises the honest deposit /
// withdraw path end-to-end without the attacker donating to inflate pool.balance.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
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
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  admin: unknown;
  adminAddress: string;
  user: unknown;
  userAddress: string;
}

async function findPool(ctx: FunctionalContext): Promise<string> {
  const poolType = `${ctx.packageId}::reward_pool::RewardPool`;
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
          change.objectType === poolType &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: could not locate the shared RewardPool");
}

async function findOne(
  ctx: FunctionalContext,
  owner: string,
  structType: string,
  label: string,
): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner,
    filter: { StructType: structType },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error(`functional: ${label} not found`);
  return id;
}

async function run(
  ctx: FunctionalContext,
  signer: unknown,
  build: (tx: Transaction) => void,
  sender: string,
  what: string,
) {
  const tx = new Transaction();
  tx.setSender(sender);
  build(tx);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`functional: ${what} failed`);
  await ctx.client.core.waitForTransaction({ result: res });
}

const COIN = (ctx: FunctionalContext) =>
  `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`;

export async function attack(ctx: FunctionalContext): Promise<void> {
  const poolId = await findPool(ctx);

  // 1) attacker (first depositor): deposit 100,000 ASSET -> nonzero shares.
  const attackerCoin = await findOne(
    ctx,
    ctx.attackerAddress,
    COIN(ctx),
    "attacker ASSET coin",
  );
  await run(
    ctx,
    ctx.attacker,
    (tx) => {
      const [stake] = tx.splitCoins(tx.object(attackerCoin), [
        tx.pure.u64(100000),
      ]);
      const share = tx.moveCall({
        target: `${ctx.packageId}::reward_pool::deposit`,
        arguments: [tx.object(poolId), stake],
      });
      tx.transferObjects([share], ctx.attackerAddress);
    },
    ctx.attackerAddress,
    "attacker deposit",
  );

  // 2) VICTIM: deposit their 100,000 ASSET -> proportional NONZERO shares.
  const victimCoin = await findOne(
    ctx,
    ctx.userAddress,
    COIN(ctx),
    "victim ASSET coin",
  );
  await run(
    ctx,
    ctx.user,
    (tx) => {
      const share = tx.moveCall({
        target: `${ctx.packageId}::reward_pool::deposit`,
        arguments: [tx.object(poolId), tx.object(victimCoin)],
      });
      tx.transferObjects([share], ctx.userAddress);
    },
    ctx.userAddress,
    "victim deposit",
  );

  // 3) attacker: withdraw their shares -> gets ~their deposit back (net ~0).
  const shareId = await findOne(
    ctx,
    ctx.attackerAddress,
    `${ctx.packageId}::reward_pool::ShareToken`,
    "attacker ShareToken",
  );
  await run(
    ctx,
    ctx.attacker,
    (tx) => {
      const coin = tx.moveCall({
        target: `${ctx.packageId}::reward_pool::withdraw`,
        arguments: [tx.object(poolId), tx.object(shareId)],
      });
      tx.transferObjects([coin], ctx.attackerAddress);
    },
    ctx.attackerAddress,
    "attacker withdraw",
  );
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
