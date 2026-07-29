// Functional (legit-behavior) check for `capability_leak` — see ../sources/vault.move.
//
// A CORRECT patch removes `request_admin_status`'s free AdminCap mint (or gates
// it to the deployer) WITHOUT breaking the legitimate admin path: the deployer,
// who holds the sole init-minted `AdminCap`, must still be able to `withdraw`
// from the shared `Vault` using that cap. This exercises exactly that path:
//
//   1. locate the shared Vault (created in init) and the admin's init AdminCap,
//   2. admin deposits ~1 SUI into the vault (so there's something to withdraw),
//   3. admin withdraws it back using their AdminCap and keeps the coin.
//
// If any of these transactions abort, the patch broke legitimate admin usage and
// the functional check fails. A correct fix leaves this path fully intact.
//
// This file exports `attack(ctx)` — the same AttackContext shape the confirmer's
// in-container runner (src/confirmer/runner.ts) invokes — so the existing
// container plumbing runs it unchanged. `functional` is exported as an alias for
// readability at the call site; the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
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
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  admin: unknown;
  adminAddress: string;
}

const DEPOSIT_MIST = 1_000_000_000n; // ~1 SUI

async function findAdminCap(ctx: FunctionalContext): Promise<string> {
  const capType = `${ctx.packageId}::vault::AdminCap`;
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: capType },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: admin does not hold the init AdminCap");
  return id;
}

// The Vault is a shared object created in `init` (published by the admin), so
// scan the admin's publish transaction's object changes for the created Vault.
async function findVault(ctx: FunctionalContext): Promise<string> {
  const vaultType = `${ctx.packageId}::vault::Vault`;
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.adminAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data) {
      for (const change of tx.objectChanges ?? []) {
        if (
          change.type === "created" &&
          change.objectType === vaultType &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: could not locate the shared Vault");
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
    throw new Error(`functional: ${label} transaction failed`);
  }
  await ctx.client.core.waitForTransaction({ result: res });
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const capId = await findAdminCap(ctx);
  const vaultId = await findVault(ctx);

  // 1) admin deposits ~1 SUI into the shared vault (a legit, permissionless op).
  const depTx = new Transaction();
  depTx.setSender(ctx.adminAddress);
  const [coin] = depTx.splitCoins(depTx.gas, [depTx.pure.u64(DEPOSIT_MIST)]);
  depTx.moveCall({
    target: `${ctx.packageId}::vault::deposit`,
    arguments: [depTx.object(vaultId), coin],
  });
  await send(ctx, depTx, "deposit");

  // 2) admin withdraws it back using their init AdminCap — the legitimate path a
  //    correct patch must preserve.
  const wdTx = new Transaction();
  wdTx.setSender(ctx.adminAddress);
  const withdrawn = wdTx.moveCall({
    target: `${ctx.packageId}::vault::withdraw`,
    arguments: [
      wdTx.object(capId),
      wdTx.object(vaultId),
      wdTx.pure.u64(DEPOSIT_MIST),
    ],
  });
  wdTx.transferObjects([withdrawn], ctx.adminAddress);
  await send(ctx, wdTx, "withdraw");
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
