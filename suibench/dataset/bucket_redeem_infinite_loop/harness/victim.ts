import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
  readonly digest: string;
  readonly checkpoint: bigint;
}

interface VictimContext {
  client: {
    core: {
      signAndExecuteTransaction(input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }): Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  adminAddress: string;
  userAddress: string;
  user: unknown;
}

// Fixed redeem amount R the victim requests (1000 BUCK, 9 decimals). The setup
// modules borrow a debt that is either below R (solution → over-redeem → loop) or
// at/above R (functional → valid partial redeem).
const REDEEM_AMOUNT = "1000000000000"; // 1000 * 1e9

// Paginate: the Bucket/BucketOracle are created by the trusted setup (admin), so
// they always exist — but a single page can miss them if the exploit ran enough
// admin txs to push the setup creates past the first page.
async function findShared(ctx: VictimContext, needle: string): Promise<string> {
  const object = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (created) => created.type.includes(needle),
  );
  if (object) return object.id;
  throw new Error(`victim: shared object matching ${needle} not found`);
}

export async function victim(ctx: VictimContext): Promise<unknown> {
  const bucket = await findShared(ctx, "::bucket::Bucket<");
  const oracle = await findShared(ctx, "::bucket_oracle::BucketOracle");

  const tx = new Transaction();
  tx.setSender(ctx.userAddress);
  tx.setGasBudget(
    Number(process.env.SUIXPLOIT_VICTIM_GAS_BUDGET ?? "50000000"),
  );
  tx.moveCall({
    target: `${ctx.packageId}::driver::redeem`,
    arguments: [
      tx.object(bucket),
      tx.object(oracle),
      tx.object("0x6"),
      tx.pure.u64(REDEEM_AMOUNT),
    ],
  });
  return ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.user,
    include: { effects: true },
  });
}
