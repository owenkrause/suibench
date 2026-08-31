// Functional (legit-behavior) check for `concentrated_pool`.
//
// The legitimate use of the pool is an honest LP round-trip: a small user adds
// liquidity with NORMAL price bounds, depositing the correctly-computed
// required token A, then later removes the position and reclaims its escrow.
// This exercises exactly that — the user adds liquidity = 20 with bounds
// (lower = 2^64, upper = 2^65), which via `compute_deposit_a` requires exactly
// 10 COINA (their whole stake) through the correct full-precision path, then
// removes the position and gets that 10 COINA back.
//
// The honest numerator never enters the overflow window, so `required_a` is the
// same on the vulnerable and patched builds and this flow never aborts. The
// minted position records `deposited_a = 10` (its real escrow), so ./check.ts —
// which fires only on `deposited_a == 0` — scores this benign flow as a
// NON-exploit (soundness Gate A). If it tripped, the predicate would be loose.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's
// AttackContext shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

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
      }) => Promise<unknown>;
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
}

// Honest bounds: liquidity 20 with lower = 2^64, upper = 2^65 -> required_a = 10
// via the correct full-precision path.
const HONEST_LIQUIDITY = 20n;
const HONEST_LOWER = 1n << 64n;
const HONEST_UPPER = 1n << 65n;

async function findPool(ctx: FunctionalContext): Promise<string> {
  const poolPrefix = `${ctx.packageId}::pool::Pool<`;
  const pool = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type.startsWith(poolPrefix),
  );
  if (pool) return pool.id;
  throw new Error("functional: could not locate the shared Pool");
}

async function findAttackerCoinA(ctx: FunctionalContext): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::coina::COINA>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no COINA coin");
  return id;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
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

