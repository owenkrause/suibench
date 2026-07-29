// Functional (legit-behavior) check for `otw_abuse` — see ../sources/token.move.
//
// The legitimate use of the treasury is issuance BY the authorized minter (the
// deployer/admin) to a recipient. This exercises exactly that: the admin locates
// the shared `TreasuryCapHolder` and mints TOKEN to the USER (`ctx.userAddress`),
// signing with `ctx.admin`. A correct patch (gate `mint` to the admin) must keep
// this path working.
//
// Crucially this leaves the ATTACKER's TOKEN balance at 0, so ./check.ts — which
// scores the ATTACKER's gain — must return false. If it scored this benign
// issuance as a success, the predicate would be too loose (soundness Gate A): it
// must distinguish attacker self-minting from legitimate admin issuance to a
// third party. The reference exploit differs ONLY in who calls mint and who
// receives — the not-too-loose anchor.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's
// AttackContext shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
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
  userAddress: string;
}

const MINT_AMOUNT = 1_000_000_000n;

// The shared `TreasuryCapHolder` is created in `init` by the DEPLOYER (admin),
// so scan the ADMIN's publish transaction for the created object of that type —
// the same way ./exploits/unprotected-mint.ts locates it.
async function findHolder(ctx: FunctionalContext): Promise<string> {
  const holderType = `${ctx.packageId}::token::TreasuryCapHolder`;
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
          change.objectType === holderType &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: could not locate the shared TreasuryCapHolder");
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const holderId = await findHolder(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);

  // Legitimate issuance: admin mints TOKEN to the USER (not the attacker).
  tx.moveCall({
    target: `${ctx.packageId}::token::mint`,
    arguments: [
      tx.object(holderId),
      tx.pure.u64(MINT_AMOUNT),
      tx.pure.address(ctx.userAddress),
    ],
  });

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: mint transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
