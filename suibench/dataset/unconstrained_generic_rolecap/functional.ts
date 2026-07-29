// Benign functional flow: the LEGITIMATE admin (the deployer, who holds the genuine
// RoleCap<AdminRole> minted to them in init) withdraws from the Treasury with their
// real admin cap and keeps the funds themselves. This is the intended, authorized
// use of `withdraw` — no escalation, no attacker involvement — so the attacker's
// ASSET balance is unchanged and ./check.ts must NOT trip.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
    getOwnedObjects(i: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
    queryTransactionBlocks(i: {
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
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<unknown>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  admin: unknown;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

async function findTreasury(ctx: FunctionalContext): Promise<string> {
  const prefix = `${ctx.packageId}::access_control::Treasury`;
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (c.type === "created" && c.objectType === prefix && c.objectId)
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: Treasury not found");
}

async function findAdminCap(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: {
      StructType: `${ctx.packageId}::access_control::RoleCap<${ctx.packageId}::access_control::AdminRole>`,
    },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: admin holds no RoleCap<AdminRole>");
  return id;
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const treasury = await findTreasury(ctx);
  const adminCap = await findAdminCap(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const coin = tx.moveCall({
    target: `${ctx.packageId}::access_control::withdraw`,
    arguments: [tx.object(adminCap), tx.object(treasury), tx.pure.u64(1000)],
  });
  tx.transferObjects([coin], ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}
export const functional = attack;
