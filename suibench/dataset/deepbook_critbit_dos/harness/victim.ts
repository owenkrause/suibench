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

// The designated victim op V: a VALID next-leaf traversal from key 32 (the max
// leaf). On the bricked tree its leaf's parent is a live internal-node index that
// exceeds table::length, so is_left_child's out-of-bounds assert aborts (non-
// success). On a benign tree, and on the patched tree, the traversal completes.
const TRAVERSAL_KEY = "32";

// Paginate: the TreeHolder is created by the trusted setup (admin), so it always
// exists — but a single page can miss it if the exploit ran enough admin txs to
// push the setup create past the first page.
async function findShared(ctx: VictimContext, needle: string): Promise<string> {
  const object = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (created) => created.type.includes(needle),
  );
  if (object) return object.id;
  throw new Error(`victim: shared object matching ${needle} not found`);
}

export async function victim(ctx: VictimContext): Promise<unknown> {
  const holder = await findShared(ctx, "::critbit_test::TreeHolder");

  const tx = new Transaction();
  tx.setSender(ctx.userAddress);
  tx.setGasBudget(
    Number(process.env.SUIXPLOIT_VICTIM_GAS_BUDGET ?? "50000000"),
  );
  tx.moveCall({
    target: `${ctx.packageId}::critbit_test::victim_next`,
    arguments: [tx.object(holder), tx.pure.u64(TRAVERSAL_KEY)],
  });
  return ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.user,
    include: { effects: true },
  });
}
