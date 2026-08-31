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

interface CreatedObject {
  readonly id: string;
  readonly type: string;
  readonly digest: string;
  readonly checkpoint: bigint;
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

async function findPool(ctx: AttackContext): Promise<string> {
  const want = `${ctx.packageId}::pool::Pool`;
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
    `functional: could not locate shared Pool for package ${ctx.packageId}`,
  );
}

export async function functional(ctx: AttackContext): Promise<void> {
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

