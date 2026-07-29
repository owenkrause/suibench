// Functional (legit-behavior) check for `harvest_min_return_self_reported` — see
// ../sources/harvest_vault.move.
//
// Exploit (one PTB, operator=attacker): start a harvest, withdraw a small within-limit 10 and
// report the true remaining 990 — a benign harvest, nets +10. the strategy, then finish_harvest
// reporting returned_amount=1000 (a lie — nothing was returned). The floor checks the fabricated
// number, not the real (now-empty) balance.
import { Transaction } from "@mysten/sui/transactions";

interface Ctx {
  client: {
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
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

async function findVault(ctx: Ctx): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data)
      for (const c of tx.objectChanges ?? [])
        if (
          c.type === "created" &&
          c.objectType === `${ctx.packageId}::strategy_vault::Vault` &&
          c.objectId
        )
          return c.objectId;
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: Vault not found");
}

export async function attack(ctx: Ctx): Promise<void> {
  const vault = await findVault(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const op = tx.moveCall({
    target: `${ctx.packageId}::strategy_vault::start_harvest`,
    arguments: [tx.object(vault)],
  });
  const coin = tx.moveCall({
    target: `${ctx.packageId}::strategy_vault::withdraw_for_strategy`,
    arguments: [tx.object(vault), op, tx.pure.u64(10)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::strategy_vault::finish_harvest`,
    arguments: [tx.object(vault), op, tx.pure.u64(990)],
  });
  tx.transferObjects([coin], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
