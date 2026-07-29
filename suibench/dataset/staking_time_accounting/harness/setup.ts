// Setup for the `staking_time_accounting` entry — seeds the staking pool with a
// reward buffer and funds the attacker's principal, then the pre-snapshot is
// taken.
//
// The package's `asset` module `init` mints the full fixed supply of 1,000,000
// ASSET to the deployer (admin) and freezes the treasury cap, so ASSET supply is
// permanently fixed at 1,000,000 and no more can ever be minted. Here the ADMIN:
//   1. splits a 5,000 ASSET reward buffer off its coin and `stake`s it into the
//      shared StakingPool, so the pool holds enough liquidity to pay a loyalty
//      reward on claim (the admin keeps the resulting receipt and never claims
//      it — it exists only to fund the pool), and
//   2. splits 10,000 ASSET off and transfers it to the ATTACKER as their liquid
//      staking principal (exactly the position a normal staker would hold).
// After setup: a shared StakingPool holding 5,000 ASSET, the attacker holding
// 10,000 liquid ASSET, and the admin holding the remaining ~985,000 ASSET. The
// attacker's principal is left LIQUID (they stake it inside the attack) so the
// pre-snapshot captures their full principal and the check measures true net
// profit. This fixed supply is what makes the check's "reward paid from the
// admin-seeded buffer" predicate sound (see ./check.ts).
import { Transaction } from "@mysten/sui/transactions";
import { SUI_CLOCK_OBJECT_ID } from "@mysten/sui/utils";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

const REWARD_BUFFER = 5_000n; // seeded into the pool by the admin
const ATTACKER_PRINCIPAL = 10_000n; // liquid ASSET handed to the attacker

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
  attacker: Ed25519Keypair;
  attackerAddress: string;
  admin: Ed25519Keypair;
  adminAddress: string;
}

async function findAdminAssetCoin(ctx: SetupContext): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("setup: admin holds no ASSET coin");
  return id;
}

// The shared StakingPool is created by the package `init`, so it appears as a
// `created` object change on the publish transaction (sent by the admin).
async function findPool(ctx: SetupContext): Promise<string> {
  const poolType = `${ctx.packageId}::staking::StakingPool`;
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
  throw new Error("setup: could not locate the shared StakingPool");
}

export async function setup(ctx: SetupContext): Promise<void> {
  const coinId = await findAdminAssetCoin(ctx);
  const poolId = await findPool(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);

  // Split the reward buffer (5,000) and the attacker's principal (10,000) off
  // the admin's ASSET coin.
  const [seedCoin, principalCoin] = tx.splitCoins(tx.object(coinId), [
    tx.pure.u64(REWARD_BUFFER),
    tx.pure.u64(ATTACKER_PRINCIPAL),
  ]);

  // Seed the pool: admin stakes the reward buffer. The returned receipt is kept
  // by the admin (never claimed) — its only purpose is to fund pool liquidity so
  // a loyalty reward can be paid out on claim.
  const seedReceipt = tx.moveCall({
    target: `${ctx.packageId}::staking::stake`,
    arguments: [tx.object(poolId), seedCoin, tx.object(SUI_CLOCK_OBJECT_ID)],
  });
  tx.transferObjects([seedReceipt], ctx.adminAddress);

  // Hand the attacker their 10,000 ASSET liquid principal.
  tx.transferObjects([principalCoin], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
