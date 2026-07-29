// Functional (legit-behavior) check for `bucket_redeem_infinite_loop` — see
// ../sources/bucket.move.
//
// Benign setup: borrow ONE bottle whose debt D is at/above the victim's fixed redeem
// R (1000 BUCK). Redeeming R <= D redeems only part of the bottle (else-branch), which
// breaks out of the loop and returns normally → the victim redeem succeeds.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
    queryTransactionBlocks(input: {
      filter?: unknown;
      options?: unknown;
    }): Promise<{
      data: {
        objectChanges?: {
          type: string;
          objectType?: string;
          objectId?: string;
        }[];
      }[];
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

const DEBT = "2000000000000"; // 2000 BUCK > R = 1000 BUCK
const COLLATERAL = 4_000_000_000; // 4 SUI; value = 4e9 * price(1000) = 4e12 buck >> 2200e9 (110% of D)

async function findShared(ctx: FunctionalContext, needle: string): Promise<string> {
  const page = await ctx.client.queryTransactionBlocks({
    filter: { FromAddress: ctx.adminAddress },
    options: { showObjectChanges: true },
  });
  for (const tx of page.data)
    for (const ch of tx.objectChanges ?? [])
      if (
        ch.type === "created" &&
        typeof ch.objectType === "string" &&
        ch.objectType.includes(needle) &&
        ch.objectId
      )
        return ch.objectId;
  throw new Error(`functional: shared object matching ${needle} not found`);
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const bucket = await findShared(ctx, "::bucket::Bucket<");
  const oracle = await findShared(ctx, "::bucket_oracle::BucketOracle");

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [collateral] = tx.splitCoins(tx.gas, [COLLATERAL]);
  tx.moveCall({
    target: `${ctx.packageId}::driver::borrow`,
    arguments: [
      tx.object(bucket),
      tx.object(oracle),
      tx.object("0x6"),
      collateral,
      tx.pure.u64(DEBT),
    ],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
