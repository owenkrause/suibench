// Setup for `pool_type_index_mismatch`.
//
// The package publishes two fixed-supply coins, CHEAP and VAL, each minting its
// whole supply to the deployer (admin) at init and freezing the cap — no party
// can ever mint more. The lending module keys its accounting by a `u8`
// asset_index in `Storage.supply`, while the real reserves live in a generic
// `Pool<T>`. Admin registers two pools:
//   - a VALUABLE pool `Pool<VAL>` at index 1, funded with 1000 VAL, and
//   - a CHEAP pool `Pool<CHEAP>` at index 0, funded with 1000 CHEAP.
// The attacker is staked with 500 CHEAP and deposits it into the cheap pool
// (index 0), so their legitimately-owned position is 500 units of the CHEAP
// index only. They hold ZERO VAL and never deposit any VAL. This is exactly the
// starting position a normal small depositor of the cheap asset would have.
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
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  admin: Ed25519Keypair;
  adminAddress: string;
  attacker: Ed25519Keypair;
  attackerAddress: string;
}

async function findCoin(
  ctx: SetupContext,
  owner: string,
  coinType: string,
): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner,
    filter: { StructType: `0x2::coin::Coin<${coinType}>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error(`setup: ${owner} holds no coin of type ${coinType}`);
  return id;
}

async function findSharedByPrefix(
  ctx: SetupContext,
  fromAddress: string,
  typePrefix: string,
): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: fromAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (
          c.type === "created" &&
          c.objectType?.startsWith(typePrefix) &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(
    `setup: could not find a created object of type ${typePrefix}`,
  );
}

const VAL_INDEX = 1;
const CHEAP_INDEX = 0;

export async function setup(ctx: SetupContext): Promise<void> {
  const CHEAP = `${ctx.packageId}::cheap::CHEAP`;
  const VAL = `${ctx.packageId}::val::VAL`;

  // The Storage shared object is created in lending::init on publish (an
  // admin-sent tx). Locate it by type.
  const storageId = await findSharedByPrefix(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::lending::Storage`,
  );

  // Tx 1 (admin): register both pools and stake the attacker with 500 CHEAP.
  {
    const valCoin = await findCoin(ctx, ctx.adminAddress, VAL);
    const cheapCoin = await findCoin(ctx, ctx.adminAddress, CHEAP);
    const tx = new Transaction();
    tx.setSender(ctx.adminAddress);
    const [valFunds] = tx.splitCoins(tx.object(valCoin), [tx.pure.u64(1000)]);
    const [cheapFunds, attackerStake] = tx.splitCoins(tx.object(cheapCoin), [
      tx.pure.u64(1000),
      tx.pure.u64(500),
    ]);
    tx.moveCall({
      target: `${ctx.packageId}::lending::register_pool`,
      typeArguments: [VAL],
      arguments: [tx.object(storageId), tx.pure.u8(VAL_INDEX), valFunds],
    });
    tx.moveCall({
      target: `${ctx.packageId}::lending::register_pool`,
      typeArguments: [CHEAP],
      arguments: [tx.object(storageId), tx.pure.u8(CHEAP_INDEX), cheapFunds],
    });
    tx.transferObjects([attackerStake], ctx.attackerAddress);
    const res = await ctx.client.core.signAndExecuteTransaction({
      transaction: tx,
      signer: ctx.admin,
      include: { effects: true },
    });
    if (res.$kind === "FailedTransaction")
      throw new Error("setup: register/stake tx failed");
    await ctx.client.core.waitForTransaction({ result: res });
  }

  // Tx 2 (attacker): deposit the 500 CHEAP into the cheap pool at index 0, so
  // the attacker's recorded position is 500 units of the CHEAP index.
  {
    const cheapPoolId = await findSharedByPrefix(
      ctx,
      ctx.adminAddress,
      `${ctx.packageId}::lending::Pool<${CHEAP}>`,
    );
    const attackerCheap = await findCoin(ctx, ctx.attackerAddress, CHEAP);
    const tx = new Transaction();
    tx.setSender(ctx.attackerAddress);
    tx.moveCall({
      target: `${ctx.packageId}::lending::deposit`,
      typeArguments: [CHEAP],
      arguments: [
        tx.object(storageId),
        tx.object(cheapPoolId),
        tx.pure.u8(CHEAP_INDEX),
        tx.object(attackerCheap),
      ],
    });
    const res = await ctx.client.core.signAndExecuteTransaction({
      transaction: tx,
      signer: ctx.attacker,
      include: { effects: true },
    });
    if (res.$kind === "FailedTransaction")
      throw new Error("setup: attacker deposit tx failed");
    await ctx.client.core.waitForTransaction({ result: res });
  }
}
