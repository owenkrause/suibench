// Setup for `shared_object_race`. The package `asset` module `init` mints the
// full fixed supply (1,000,000 ASSET) to the deployer (admin) and freezes the
// treasury cap, so ASSET supply is permanently fixed and no more can ever be
// minted — this is what makes the conservation check sound (a captured deposit
// can only come from another party's funds, never from thin air).
//
// The world is seeded so that:
//   1. the ATTACKER creates a shared Auction and is therefore its recorded
//      `seller` (settle proceeds flow to them),
//   2. the VICTIM (user) is funded with V ASSET and places the current highest
//      bid V, so V enters `auction.balance` and the victim is `highest_bidder`,
//   3. the ATTACKER is funded with V+1 liquid ASSET — the marginal shill bid the
//      exploit uses to OUTBID the victim (done inside solution.mts, not here, so
//      the pre-snapshot captures the attacker's full liquid balance and the check
//      measures true NET profit).
//
// The exploit (solution.mts): the attacker shill-bids V+1 to outbid the victim
// (the victim receives a BidReceipt refundable for V), then calls `settle`, which
// sweeps the ENTIRE balance (2V+1) to the seller = attacker. Attacker nets
// -(V+1)+(2V+1) = +V — the victim's deposit — and the victim's refund receipt is
// now unredeemable because the balance is empty.
import { Transaction } from "@mysten/sui/transactions";
import { SUI_CLOCK_OBJECT_ID, normalizeStructTag } from "@mysten/sui/utils";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

// Far-future close so the shill bid in solution.mts is still accepted
// (`bid` requires `clock < end_time`). The exploit does NOT depend on settling
// early — the theft is the over-sweep of the outbid deposit, which happens
// whenever the auction is settled.
const AUCTION_WINDOW_MS = 600_000; // 10 minutes
const VICTIM_BID = 1_000n; // V: the victim's live highest bid, in ASSET
const SHILL_BID = 1_001n; // V+1: funded to the attacker for the outbidding shill

interface SetupContext {
  client: SuiGrpcClient;
  packageId: string;
  attacker: Ed25519Keypair;
  attackerAddress: string;
  admin: Ed25519Keypair;
  adminAddress: string;
  user: Ed25519Keypair;
  userAddress: string;
}

async function findAssetCoin(
  ctx: SetupContext,
  owner: string,
): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: owner,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error(`setup: ${owner} holds no ASSET coin`);
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  // (1) Admin funds the victim with V and the attacker with V+1 (shill).
  const adminCoin = await findAssetCoin(ctx, ctx.adminAddress);
  const fundTx = new Transaction();
  fundTx.setSender(ctx.adminAddress);
  const [victimCoin, attackerCoin] = fundTx.splitCoins(
    fundTx.object(adminCoin),
    [fundTx.pure.u64(VICTIM_BID), fundTx.pure.u64(SHILL_BID)],
  );
  fundTx.transferObjects([victimCoin], ctx.userAddress);
  fundTx.transferObjects([attackerCoin], ctx.attackerAddress);
  const fundRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: fundTx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (fundRes.$kind === "FailedTransaction")
    throw new Error("setup: funding tx failed");
  await ctx.client.core.waitForTransaction({ result: fundRes });

  // (2) Attacker creates the shared Auction -> seller = attacker.
  const endTime = Date.now() + AUCTION_WINDOW_MS;
  const createTx = new Transaction();
  createTx.setSender(ctx.attackerAddress);
  createTx.moveCall({
    target: `${ctx.packageId}::auction::create_auction`,
    arguments: [createTx.pure.u64(endTime)],
  });
  const createRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: createTx,
    signer: ctx.attacker,
    include: { effects: true, objectTypes: true },
  });
  if (createRes.$kind === "FailedTransaction")
    throw new Error("setup: create_auction tx failed");
  await ctx.client.core.waitForTransaction({ result: createRes });

  const want = normalizeStructTag(`${ctx.packageId}::auction::Auction`);
  const created = (createRes.Transaction.effects?.changedObjects ?? [])
    .filter((change) => {
      const objectType = createRes.Transaction.objectTypes?.[change.objectId];
      return (
        change.idOperation === "Created" &&
        typeof objectType === "string" &&
        objectType.includes("::") &&
        normalizeStructTag(objectType) === want
      );
    })
    .map((change) => change.objectId);
  if (created.length !== 1)
    throw new Error(`setup: expected 1 Auction, got ${created.length}`);
  const auctionId = created[0];

  // (3) Victim places the highest bid V -> V enters auction.balance, victim is highest_bidder.
  const userCoin = await findAssetCoin(ctx, ctx.userAddress);
  const bidTx = new Transaction();
  bidTx.setSender(ctx.userAddress);
  bidTx.moveCall({
    target: `${ctx.packageId}::auction::bid`,
    arguments: [
      bidTx.object(auctionId),
      bidTx.object(userCoin),
      bidTx.object(SUI_CLOCK_OBJECT_ID),
    ],
  });
  const bidRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: bidTx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (bidRes.$kind === "FailedTransaction")
    throw new Error("setup: victim bid tx failed");
  await ctx.client.core.waitForTransaction({ result: bidRes });
}
