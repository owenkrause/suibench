// Setup for unconstrained_generic_rolecap. Admin (deployer) holds the fixed ASSET
// supply and the genuine RoleCap<AdminRole> minted in init. The shared Treasury is
// created empty by init; here the admin funds it with 1000 ASSET via `deposit` so
// there is real value for an escalated attacker to drain (and for the legit admin
// to withdraw benignly in the functional run).
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
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  admin: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}

async function findTreasury(ctx: SetupContext): Promise<string> {
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
  throw new Error("setup: Treasury not found");
}

export async function setup(ctx: SetupContext): Promise<void> {
  const ASSET = `${ctx.packageId}::asset::ASSET`;
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${ASSET}>` },
    options: { showType: true },
  });
  const adminCoin = owned.data[0]?.data?.objectId;
  if (!adminCoin) throw new Error("setup: admin holds no ASSET");

  const treasury = await findTreasury(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [fund] = tx.splitCoins(tx.object(adminCoin), [tx.pure.u64(1000)]);
  tx.moveCall({
    target: `${ctx.packageId}::access_control::deposit`,
    arguments: [tx.object(treasury), fund],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: deposit tx failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
