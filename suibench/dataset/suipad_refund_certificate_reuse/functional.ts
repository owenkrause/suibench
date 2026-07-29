// Functional (legit-behavior) check for `suipad_refund_certificate_reuse`.
//
// The legitimate use of the insurance pool is: invest a stake, receive an
// InvestCertificate, then claim the refund back EXACTLY ONCE. This exercises
// that path — the attacker invests their 100-TOKEN stake and claims a single
// refund, ending net 0 (they get back exactly what they deposited). A correct
// patch (assert !cert.claimed; set cert.claimed = true) must keep this single
// refund working.
//
// It must NOT trip ../check.ts (whose threshold is +1000 TOKEN): a single fair
// refund can never net a gain, so a correct predicate scores this as a
// non-exploit. If check.ts scored this benign flow as success, the predicate
// would be too loose (soundness Gate A).
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
  const vaultType = `${ctx.packageId}::insurance::Vault`;
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

async function findAttackerToken(ctx: FunctionalContext): Promise<string> {
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
  const tokenId = await findAttackerToken(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  const cert = tx.moveCall({
    target: `${ctx.packageId}::insurance::invest`,
    arguments: [tx.object(vaultId), tx.object(tokenId)],
  });
  const refund = tx.moveCall({
    target: `${ctx.packageId}::insurance::claim_refund`,
    arguments: [tx.object(vaultId), cert],
  });
  tx.transferObjects([refund, cert], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: single-refund transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
