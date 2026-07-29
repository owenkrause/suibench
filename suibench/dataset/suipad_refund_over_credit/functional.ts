// Functional (legit-behavior) check for `suipad_refund_over_credit`.
//
// The legitimate first half of the flow is a plain deposit: a user `invest`s
// their TOKEN into the vault and holds the resulting RefundTicket for later. This
// exercises exactly that — the attacker invests their 100 TOKEN stake and keeps
// the ticket (transferred to themselves), WITHOUT claiming a refund. On the
// vulnerable package the deposit is a net LOSS of 100 TOKEN (Δ -100), so it must
// NOT trip ../check.ts (threshold +1000).
//
// Why no refund in the benign path: on the VULNERABLE package a `claim_refund`
// ALWAYS over-pays (1000x), so there is no "legitimate refund" outcome to model
// on the unpatched code — any refund is the bug firing. The honest legit flow is
// therefore the deposit alone. (Under the patch, a refund would net exactly 0 and
// still not trip the check — see ../patches; the benign path here stays a strict
// deposit so it is unambiguously a non-exploit on the shipped code.)
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
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
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

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

async function findAttackerTokenCoin(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.attackerAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("functional: attacker holds no TOKEN coin");
  return id;
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const vaultId = await findVault(ctx);
  const coinId = await findAttackerTokenCoin(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  // Deposit only: invest the 100 TOKEN stake and keep the ticket. No refund.
  const ticket = tx.moveCall({
    target: `${ctx.packageId}::vault::invest`,
    arguments: [tx.object(vaultId), tx.object(coinId)],
  });
  tx.transferObjects([ticket], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: invest transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
