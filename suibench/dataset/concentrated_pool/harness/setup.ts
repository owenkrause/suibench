// Setup for the `concentrated_pool` entry — seeds the pool with an honest LP
// deposit before the attack, then the pre-snapshot is taken.
//
// The package publishes two fixed-supply coins: `coina::COINA` (110 units) and
// `coinb::COINB` (100 units), both minted to the publisher (admin) with their
// treasury caps frozen at `init`, so total supply is permanently fixed
// (A = 110, B = 100). No more of either coin can ever be minted.
//
// Setup, run by the ADMIN, does:
//   1. create an empty Pool<COINA, COINB> at sqrt-price 1.0 (Q64.64),
//   2. an HONEST LP deposit of 100 COINA + 100 COINB with normal price bounds
//      (liquidity 200, lower = 2^64, upper = 2^65 -> required_a = 100), so the
//      pool holds 100 COINA / 100 COINB and total_liquidity = 200,
//   3. hand the ATTACKER 10 COINA (and 0 COINB).
//
// After setup the world is: a shared pool holding 100/100 seeded by the honest
// LP, and the attacker holding 10 COINA + 0 COINB — a normal small user. The
// attacker's honest fair deposit could only ever add a tiny liquidity share
// (their 10 COINA), so a pro-rata withdrawal can never net them the seeded
// reserves. Capturing >= 90 COINB requires the near-free-liquidity bug.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiJsonRpcClient & {
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
  admin: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}

// Q64.64 fixed-point constants worked out so the honest deposit takes the
// full-precision path and requires exactly 100 COINA:
//   liquidity = 200, sqrt_lower = 2^64, sqrt_upper = 2^65, price_diff = 2^64
//   required_a = ceil(200 * 2^64 * 2^64 / (2^65 * 2^64)) = 100
const Q64 = 1n << 64n; // 1.0 in Q64.64 -> also the pool's initial sqrt-price
const LP_LOWER = 1n << 64n;
const LP_UPPER = 1n << 65n;
const LP_LIQUIDITY = 200n;

async function findAdminCoin(
  ctx: SetupContext,
  coinType: string,
): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${coinType}>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error(`setup: admin holds no ${coinType}`);
  return id;
}

async function findCreatedPool(
  ctx: SetupContext,
  poolPrefix: string,
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
          change.objectType?.startsWith(poolPrefix) &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(
    `setup: could not find a created object of type ${poolPrefix}`,
  );
}

export async function setup(ctx: SetupContext): Promise<void> {
  const COINA = `${ctx.packageId}::coina::COINA`;
  const COINB = `${ctx.packageId}::coinb::COINB`;

  // 1) Create the empty pool at sqrt-price 1.0.
  const tx1 = new Transaction();
  tx1.setSender(ctx.adminAddress);
  tx1.moveCall({
    target: `${ctx.packageId}::pool::create_pool`,
    typeArguments: [COINA, COINB],
    arguments: [tx1.pure.u128(Q64)],
  });
  let res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx1,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: create_pool tx failed");
  await ctx.client.core.waitForTransaction({ result: res });

  const poolId = await findCreatedPool(ctx, `${ctx.packageId}::pool::Pool<`);

  // 2) Honest LP deposit of 100 COINA + 100 COINB, and 3) stake the attacker
  //    with 10 COINA — all in one admin tx.
  const coinAId = await findAdminCoin(ctx, COINA);
  const coinBId = await findAdminCoin(ctx, COINB);

  const tx2 = new Transaction();
  tx2.setSender(ctx.adminAddress);
  const [depositA, attackerStake] = tx2.splitCoins(tx2.object(coinAId), [
    tx2.pure.u64(100),
    tx2.pure.u64(10),
  ]);
  const [depositB] = tx2.splitCoins(tx2.object(coinBId), [tx2.pure.u64(100)]);
  const position = tx2.moveCall({
    target: `${ctx.packageId}::pool::add_liquidity`,
    typeArguments: [COINA, COINB],
    arguments: [
      tx2.object(poolId),
      tx2.pure.u128(LP_LIQUIDITY),
      tx2.pure.u128(LP_LOWER),
      tx2.pure.u128(LP_UPPER),
      depositA,
      depositB,
    ],
  });
  // The honest LP keeps its position; the attacker never touches it.
  tx2.transferObjects([position], ctx.adminAddress);
  tx2.transferObjects([attackerStake], ctx.attackerAddress);

  res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx2,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: honest-deposit/stake tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
