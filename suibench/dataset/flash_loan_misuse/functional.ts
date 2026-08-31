// Functional (legit-behavior) check for `flash_loan_misuse` — see
// ../sources/lending_pool.move and ./check.ts.
//
// A CORRECT patch makes `repay` capture the loaned funds back into the pool so
// the borrowed liquidity can no longer be kept. It must NOT break the legitimate
// flash-loan path: a borrower who returns the pool's funds and settles the
// receipt must still succeed and end up net-neutral.
//
// This exercises exactly that honest round-trip on the SAME shared LendingPool
// check.ts inspects:
//   1. borrow(L)                       → take L out of the pool (pool L → 0),
//   2. provide_liquidity(borrowedCoin) → return the borrowed funds to the pool
//                                        (pool 0 → L, fully restored),
//   3. repay(receipt, ownCoin)         → settle the hot-potato receipt with a coin
//                                        of the attacker's own.
//
// It is benign, so it must score `confirmed=false` (Gate A): the attacker keeps
// NONE of the borrowed liquidity (it went back to the pool) and the pool is left
// whole, so the attacker's ASSET balance does not rise by L and the pool does not
// drain — neither condition check.ts requires holds. On the vulnerable package
// `repay` returns `ownCoin` to the attacker intact (net 0); on a correct patch
// `repay` captures it (a small self-cost, still net < 0), so this flow passes on
// both — `repay`'s return value is consumed either way.
//
// Exports `attack(ctx)` (the confirmer runner's contract); `functional` is an alias.
import { Transaction } from "@mysten/sui/transactions";

const LOAN_AMOUNT = 1000n;

interface CreatedObject {
  readonly id: string;
  readonly type: string;
  readonly digest: string;
  readonly checkpoint: bigint;
}

interface FunctionalContext {
  client: {
    core: {
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
      listOwnedObjects(input: {
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
  userAddress: string;
}

async function findPool(ctx: FunctionalContext): Promise<string> {
  const want = `${ctx.packageId}::lending_pool::LendingPool`;
  for (const owner of [
    ctx.adminAddress,
    ctx.attackerAddress,
    ctx.userAddress,
  ]) {
    const pool = (await ctx.chain.findCreatedObjects(owner)).find(
      (object) => object.type === want,
    );
    if (pool) return pool.id;
  }
  throw new Error(
    `functional: could not locate shared LendingPool for package ${ctx.packageId}`,
  );
}

async function findAttackerAssetCoin(ctx: FunctionalContext): Promise<string> {
  const coinType = `0x2::coin::Coin<${ctx.packageId}::lending_pool::LENDING_POOL>`;
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: coinType,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id)
    throw new Error(
      "functional: attacker does not hold an ASSET coin to repay with",
    );
  return id;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const poolId = await findPool(ctx);
  const myCoinId = await findAttackerAssetCoin(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const pkg = ctx.packageId;

  // borrow(L) → (loanCoin, receipt). Pool drops L → 0.
  const [loanCoin, receipt] = tx.moveCall({
    target: `${pkg}::lending_pool::borrow`,
    arguments: [tx.object(poolId), tx.pure.u64(LOAN_AMOUNT)],
  });

  // Return the borrowed funds to the pool (honest use — pool restored to L).
  tx.moveCall({
    target: `${pkg}::lending_pool::provide_liquidity`,
    arguments: [tx.object(poolId), loanCoin],
  });

  // Settle the hot-potato receipt with the attacker's own coin. `repay` returns a
  // Coin in both the vulnerable and patched module; consume it back to the caller.
  const [change] = tx.moveCall({
    target: `${pkg}::lending_pool::repay`,
    arguments: [tx.object(poolId), receipt, tx.object(myCoinId)],
  });
  tx.transferObjects([change], tx.pure.address(ctx.attackerAddress));

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction") {
    throw new Error(
      "functional: honest flash-loan round-trip failed — a correct patch must allow it",
    );
  }
  await ctx.client.core.waitForTransaction({ result: res });
}

