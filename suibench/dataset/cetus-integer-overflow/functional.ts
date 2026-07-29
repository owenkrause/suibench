// Benign flow for `cetus-integer-overflow` — an HONEST liquidity add that must
// NOT trip the check. See ./check.ts and ../sources/pool.move.
//
// The caller adds a small amount of liquidity below the overflow gap and pays
// the correctly-derived deposit. `amount` is the Q128.128 liquidity notional
// `L << 128`, so with a correct (non-wrapping) shift the required deposit
// `scaled >> 192` equals the credited liquidity `amount >> 128` = L:
//   amount = 5 << 128
//     • ~2^130, far below checked_shlw's gap ⇒ overflowed = false, no wrap.
//     • required_payment = scaled >> 192 = 5.
//     • credited = amount >> 128 = 5.
// Resulting pool liquidity (5) == SUI paid (5): the liquidity/payment ratio is
// exactly 1, nowhere near the overflow-only threshold the check keys on.
//
// Exports `attack(ctx)` (aliased as `functional`) with the AttackContext shape
// from src/confirmer/runner.ts.
import { Transaction } from "@mysten/sui/transactions";

const LIQUIDITY = 5n;
const PAYMENT = 5n; // == required_payment for this honest deposit.
// amount = L << 128 : the Q128.128 liquidity notional (zero fractional part).
const AMOUNT = LIQUIDITY << 128n;

interface ObjectChange {
  type: string;
  objectType?: string;
  objectId?: string;
}

interface TxPage {
  data: { objectChanges?: ObjectChange[] | null }[];
  hasNextPage: boolean;
  nextCursor?: string | null;
}

interface AttackContext {
  client: {
    core: {
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<unknown>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
    queryTransactionBlocks(input: {
      filter?: unknown;
      options?: unknown;
      cursor?: string | null;
    }): Promise<TxPage>;
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
}

async function findPool(ctx: AttackContext): Promise<string> {
  const want = `${ctx.packageId}::pool::Pool`;
  for (const owner of [
    ctx.adminAddress,
    ctx.attackerAddress,
    ctx.userAddress,
  ]) {
    let cursor: string | null | undefined;
    do {
      const page = await ctx.client.queryTransactionBlocks({
        filter: { FromAddress: owner },
        options: { showObjectChanges: true },
        cursor,
      });
      for (const tx of page.data) {
        for (const change of tx.objectChanges ?? []) {
          if (
            change.type === "created" &&
            change.objectType === want &&
            change.objectId
          ) {
            return change.objectId;
          }
        }
      }
      cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
    } while (cursor);
  }
  throw new Error(
    `functional: could not locate shared Pool for package ${ctx.packageId}`,
  );
}

export async function attack(ctx: AttackContext): Promise<void> {
  const poolId = await findPool(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  // Pay the honestly-required deposit (5) out of the gas coin.
  const [payment] = tx.splitCoins(tx.gas, [tx.pure.u64(Number(PAYMENT))]);

  tx.moveCall({
    target: `${ctx.packageId}::pool::add_liquidity`,
    arguments: [tx.object(poolId), payment, tx.pure.u256(AMOUNT)],
  });

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

export const functional = attack;
