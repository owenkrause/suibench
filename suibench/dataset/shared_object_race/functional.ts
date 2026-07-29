// Functional (legit-behavior) check for `shared_object_race` — see
// ../sources/auction.move and ./check.ts.
//
// The benign flow is the exploit's sequence WITH the refund used correctly: the
// outbid victim claims their refund BEFORE the seller settles, so no deposit is
// stranded and no theft occurs. It reuses the setup auction (attacker = seller,
// victim's V bid already in the balance, attacker funded with V+1).
//
//   tx1 — attacker shill-bids V+1, outbidding the victim (victim -> BidReceipt V);
//         balance = 2V+1.
//   tx2 — VICTIM claims their refund V (the honest, timely action); balance = V+1.
//   tx3 — attacker settles; the (vulnerable) settle sweeps the remaining V+1,
//         which is exactly the attacker's own returned shill bid.
//
// Result: attacker nets -(V+1)+(V+1) = 0 and the victim holds no outstanding
// receipt — both check clauses are false, so this scores `confirmed = false`
// (Gate A). It runs on both the vulnerable and patched contract (refunds work in
// either when claimed before settle), asserting the honest refund path is intact.
//
// Exports `attack(ctx)` (the confirmer runner's contract); `functional` is an alias.
import { Transaction } from "@mysten/sui/transactions";
import { SUI_CLOCK_OBJECT_ID } from "@mysten/sui/utils";

interface Ctx {
  client: {
    getOwnedObjects(i: {
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
  attacker: unknown;
  attackerAddress: string;
  admin: unknown;
  adminAddress: string;
  user: unknown;
  userAddress: string;
}

async function findAttackerAuction(ctx: Ctx): Promise<string> {
  const auctionType = `${ctx.packageId}::auction::Auction`;
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.attackerAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data) {
      for (const c of tx.objectChanges ?? []) {
        if (c.type === "created" && c.objectType === auctionType && c.objectId)
          return c.objectId;
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error("functional: attacker Auction not found");
}

async function findCoin(
  ctx: Ctx,
  owner: string,
  structType: string,
): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner,
    filter: { StructType: structType },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error(`functional: ${owner} holds no ${structType}`);
  return id;
}

export async function attack(ctx: Ctx): Promise<void> {
  const auction = await findAttackerAuction(ctx);
  const assetCoinType = `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`;

  // tx1 — attacker shill-bids V+1, outbidding the victim.
  const shillCoin = await findCoin(ctx, ctx.attackerAddress, assetCoinType);
  const bidTx = new Transaction();
  bidTx.setSender(ctx.attackerAddress);
  bidTx.moveCall({
    target: `${ctx.packageId}::auction::bid`,
    arguments: [
      bidTx.object(auction),
      bidTx.object(shillCoin),
      bidTx.object(SUI_CLOCK_OBJECT_ID),
    ],
  });
  const bidRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: bidTx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (bidRes.$kind === "FailedTransaction")
    throw new Error("functional: shill bid tx failed");
  await ctx.client.core.waitForTransaction({ result: bidRes });

  // tx2 — victim claims their refund BEFORE settle (the honest, timely action).
  const receipt = await findCoin(
    ctx,
    ctx.userAddress,
    `${ctx.packageId}::auction::BidReceipt`,
  );
  const refundTx = new Transaction();
  refundTx.setSender(ctx.userAddress);
  const refundCoin = refundTx.moveCall({
    target: `${ctx.packageId}::auction::claim_refund`,
    arguments: [refundTx.object(auction), refundTx.object(receipt)],
  });
  refundTx.transferObjects([refundCoin], ctx.userAddress);
  const refundRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: refundTx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (refundRes.$kind === "FailedTransaction")
    throw new Error("functional: claim_refund tx failed");
  await ctx.client.core.waitForTransaction({ result: refundRes });

  // tx3 — attacker settles; only their own returned shill bid remains.
  const settleTx = new Transaction();
  settleTx.setSender(ctx.attackerAddress);
  settleTx.moveCall({
    target: `${ctx.packageId}::auction::settle`,
    arguments: [settleTx.object(auction)],
  });
  const settleRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: settleTx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (settleRes.$kind === "FailedTransaction")
    throw new Error("functional: settle tx failed");
  await ctx.client.core.waitForTransaction({ result: settleRes });
}

export const functional = attack;
