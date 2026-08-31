// Functional (legit-behavior) check for `bucket_redeem_infinite_loop` — see
// ../sources/bucket.move.
//
// Benign setup: borrow ONE bottle whose debt D is at/above the victim's fixed redeem
// R (1000 BUCK). Redeeming R <= D redeems only part of the bottle (else-branch), which
// breaks out of the loop and returns normally → the victim redeem succeeds.
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

const DEBT = "2000000000000"; // 2000 BUCK > R = 1000 BUCK
const COLLATERAL = 4_000_000_000; // 4 SUI; value = 4e9 * price(1000) = 4e12 buck >> 2200e9 (110% of D)

async function findShared(
  ctx: FunctionalContext,
  needle: string,
): Promise<string> {
  const object = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (created) => created.type.includes(needle),
  );
  if (object) return object.id;
  throw new Error(`functional: shared object matching ${needle} not found`);
}

export async function functional(ctx: FunctionalContext): Promise<void> {
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

