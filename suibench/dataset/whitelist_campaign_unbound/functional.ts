// Functional (legit-behavior) check for `whitelist_campaign_unbound` — see
// ../sources/launchpad.move.
//
// A CORRECT patch adds `assert!(whitelist.campaign_id == id(campaign))` to
// `invest` WITHOUT breaking the legitimate path: a correctly-MATCHED invest — a
// real whitelisted member investing in the very campaign their whitelist belongs
// to — must still succeed. This exercises exactly that: the USER, who setup.ts
// added to Whitelist_A (campaign A's own list), invests in campaign A with
// Whitelist_A (the correct pair). If the patch is right this still goes through;
// if a patch over-restricts and breaks it, the functional check fails.
//
// This is exported as `attack(ctx)` because the confirmer runner only ever calls
// `attack`; here it performs a benign, correctly-bound invest.
import { Transaction } from "@mysten/sui/transactions";

interface ObjectChange {
  type: string;
  objectType?: string;
  objectId?: string;
}

interface FunctionalContext {
  client: {
    getObject(i: {
      id: string;
      options?: unknown;
    }): Promise<{
      data?: { content?: { fields?: Record<string, unknown> } | null } | null;
    }>;
    queryTransactionBlocks(i: {
      filter?: unknown;
      options?: unknown;
      cursor?: string | null;
    }): Promise<{
      data: { objectChanges?: ObjectChange[] | null }[];
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
  user: unknown;
  userAddress: string;
  adminAddress: string;
}

async function createdByOfType(
  ctx: FunctionalContext,
  creator: string,
  wantType: string,
): Promise<string[]> {
  const ids: string[] = [];
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: creator },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const t of page.data)
      for (const c of t.objectChanges ?? []) {
        if (c.type === "created" && c.objectType === wantType && c.objectId)
          ids.push(c.objectId);
      }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  return ids;
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const pkg = ctx.packageId;
  const CAMPAIGN = `${pkg}::launchpad::Campaign`;
  const WHITELIST = `${pkg}::launchpad::Whitelist`;

  // Campaign A and Whitelist_A are the admin-created gated sale + its own list.
  const campaignA = (await createdByOfType(ctx, ctx.adminAddress, CAMPAIGN))[0];
  if (!campaignA) throw new Error("functional: no admin campaign (A) found");
  const adminWhitelists = await createdByOfType(
    ctx,
    ctx.adminAddress,
    WHITELIST,
  );

  // Pick the admin whitelist that belongs to campaign A (its campaign_id matches).
  let whitelistA: string | undefined;
  for (const w of adminWhitelists) {
    const r = await ctx.client.getObject({
      id: w,
      options: { showContent: true },
    });
    if (r.data?.content?.fields?.campaign_id === campaignA) {
      whitelistA = w;
      break;
    }
  }
  if (!whitelistA)
    throw new Error("functional: no whitelist A for campaign A found");

  // The USER (a legit member of Whitelist_A) invests in campaign A with the
  // CORRECT whitelist — the legitimate path a valid patch must preserve.
  const tx = new Transaction();
  tx.setSender(ctx.userAddress);
  const [payment] = tx.splitCoins(tx.gas, [tx.pure.u64(1_000_000n)]);
  tx.moveCall({
    target: `${pkg}::launchpad::invest`,
    arguments: [tx.object(campaignA), tx.object(whitelistA), payment],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(
      "functional: matched invest (user→campaign A w/ whitelist A) failed",
    );
  await ctx.client.core.waitForTransaction({ result: res });
}

export const functional = attack;
