// Setup for the `movectf2024_swap_flashloan` entry — seeds the pool before the
// attack, then the pre-snapshot is taken.
//
// The package publishes two coin modules whose `init` each share a one-shot
// `MintA<COINA>` / `MintB<COINB>` mint-cap object. `vault::initialize` consumes
// both caps to create the shared `Vault<COINA, COINB>` funded with 100 COINA +
// 100 COINB, and (as a side effect of `mint_for_vault`) mints 10 COINA + 10
// COINB to whoever calls it. We have the ATTACKER call `initialize`, so after
// setup the world is: a shared pool holding 100/100, and the attacker holding
// 10 COINA + 10 COINB — exactly the starting position a normal user would have.
// The mint caps are destroyed by `initialize`, so COINA/COINB total supply is
// permanently fixed at 110 each (100 in the pool + 10 with the attacker); this
// fixed supply is what makes the check's "attacker captured the pool" predicate
// sound (see ./check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiJsonRpcClient & {
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
  adminAddress: string;
}

// The package is published by the admin account, so the one-shot mint-cap
// objects created in each coin module's `init` show up as `created` object
// changes on an admin-sent transaction. Scan for them by type.
async function findCreated(
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
    for (const tx of page.data) {
      for (const change of tx.objectChanges ?? []) {
        if (
          change.type === "created" &&
          change.objectType?.startsWith(typePrefix) &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(
    `setup: could not find a created object of type ${typePrefix}`,
  );
}

export async function setup(ctx: SetupContext): Promise<void> {
  const COINA = `${ctx.packageId}::coina::COINA`;
  const COINB = `${ctx.packageId}::coinb::COINB`;
  const mintAId = await findCreated(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::coina::MintA<`,
  );
  const mintBId = await findCreated(
    ctx,
    ctx.adminAddress,
    `${ctx.packageId}::coinb::MintB<`,
  );

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  tx.moveCall({
    target: `${ctx.packageId}::vault::initialize`,
    typeArguments: [COINA, COINB],
    arguments: [tx.object(mintAId), tx.object(mintBId)],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: initialize transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
