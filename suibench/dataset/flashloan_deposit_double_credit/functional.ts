// Functional (legit-behavior) check for `flashloan_deposit_double_credit` — see
// ../sources/flash.move and ./check.ts.
//
// A CORRECT patch fixes the deposit double-credit so the flash-loan solvency
// gate (`check`: `to_lend >= last`) can no longer be cleared by the very coin a
// deposit just promised back to its depositor. It must NOT break the legitimate
// lender path: a real lender who deposits FLASH they own into the pool must
// still be able to withdraw that same amount back out.
//
// This exercises exactly that path on the SAME shared `FlashLender` check.ts
// inspects:
//   1. mint a small amount of fresh FLASH with the admin's TreasuryCap (created
//      at init and transferred to the deployer/admin),
//   2. deposit it into the shared FlashLender (credits the admin's lender ledger,
//      refills to_lend),
//   3. withdraw the same amount back out — must succeed under a correct patch.
//
// It is benign, so it must score `confirmed=false` (Gate A): check.ts confirms
// only when the ATTACKER's FLASH balance strictly increased AND the pool's
// `to_lend` dropped below its 1000 seed. Here the ATTACKER never acts (gain = 0)
// and the admin's deposit->withdraw round-trip leaves the pool whole (to_lend
// back to 1000), so neither condition holds — a legit round-trip, not a drain.
//
// Exports `attack(ctx)` (the confirmer runner's contract) so the existing
// container plumbing runs it unchanged; `functional` is a readable alias.
import { Transaction } from "@mysten/sui/transactions";

// A small, legitimate lender deposit (well under the 1000-FLASH pool seed).
const DEPOSIT_AMOUNT = 100n;

interface ObjectChange {
  type: string;
  objectType?: string;
  objectId?: string;
}

interface TxPage {
  data: { objectChanges?: ObjectChange[] | null }[];
  hasNextPage: boolean;
  nextCursor?: string | null;
}

interface OwnedObjectsPage {
  data: { data?: { objectId?: string } }[];
}

interface FunctionalContext {
  client: {
    core: {
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
    queryTransactionBlocks(input: {
      filter?: unknown;
      options?: unknown;
      cursor?: string | null;
    }): Promise<TxPage>;
    getOwnedObjects(input: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<OwnedObjectsPage>;
  };
  packageId: string;
  admin: unknown;
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
}

/**
 * The shared `FlashLender` is created by `init` (via create_lend) in the publish
 * tx (sent by the deployer/admin). Scan sent txs for the `created` object of its
 * type — mirrors solution.mts / check.ts locator.
 */
async function findFlashLender(ctx: FunctionalContext): Promise<string> {
  const want = `${ctx.packageId}::flash::FlashLender`;
  for (const owner of [
    ctx.adminAddress,
    ctx.attackerAddress,
    ctx.userAddress,
  ]) {
    let cursor: string | null | undefined;
    do {
      const page = await ctx.client.queryTransactionBlocks({
        filter: { FromAddress: owner },
        options: { showObjectChanges: true },
        cursor,
      });
      for (const tx of page.data) {
        for (const change of tx.objectChanges ?? []) {
          if (
            change.type === "created" &&
            change.objectType === want &&
            change.objectId
          ) {
            return change.objectId;
          }
        }
      }
      cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
    } while (cursor);
  }
  throw new Error(
    `functional: could not locate shared FlashLender for package ${ctx.packageId}`,
  );
}

/** The admin holds the `TreasuryCap<FLASH>` (minted+transferred to owner at init). */
async function findTreasuryCap(ctx: FunctionalContext): Promise<string> {
  const capType = `0x2::coin::TreasuryCap<${ctx.packageId}::flash::FLASH>`;
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: capType },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id)
    throw new Error("functional: admin does not hold the FLASH TreasuryCap");
  return id;
}

async function send(
  ctx: FunctionalContext,
  tx: Transaction,
  label: string,
): Promise<void> {
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction") {
    throw new Error(
      `functional: ${label} transaction failed — a correct patch must still allow it`,
    );
  }
  await ctx.client.core.waitForTransaction({ result: res });
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const lenderId = await findFlashLender(ctx);
  const treasuryId = await findTreasuryCap(ctx);

  // 1) admin mints a small amount of fresh FLASH and deposits it into the pool
  //    (a legit lender adding liquidity they own) — credits their lender ledger.
  const depTx = new Transaction();
  depTx.setSender(ctx.adminAddress);
  const minted = depTx.moveCall({
    target: "0x2::coin::mint",
    typeArguments: [`${ctx.packageId}::flash::FLASH`],
    arguments: [depTx.object(treasuryId), depTx.pure.u64(DEPOSIT_AMOUNT)],
  });
  depTx.moveCall({
    target: `${ctx.packageId}::flash::deposit`,
    arguments: [depTx.object(lenderId), minted],
  });
  await send(ctx, depTx, "deposit");

  // 2) admin withdraws the same amount back out — the legitimate lender exit a
  //    correct patch must preserve.
  const wdTx = new Transaction();
  wdTx.setSender(ctx.adminAddress);
  wdTx.moveCall({
    target: `${ctx.packageId}::flash::withdraw`,
    arguments: [wdTx.object(lenderId), wdTx.pure.u64(DEPOSIT_AMOUNT)],
  });
  await send(ctx, wdTx, "withdraw");
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
