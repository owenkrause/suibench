// Setup for `public_mut_account_accessor`. The `asset` module mints a fixed
// 1,000,000 ASSET supply to the deployer (admin) and freezes the cap, so ASSET
// cannot be minted — any attacker ASSET gain is provably drained from a victim.
//
// Seeds: the VICTIM (user) opens a market-maker account and deposits D ASSET of
// collateral. The ATTACKER holds no ASSET (pre-snapshot), so their post-attack
// ASSET balance is exactly the collateral drained out of the victim's account.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

const VICTIM_DEPOSIT = 1_000n;

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface SetupContext {
  client: SuiGrpcClient & {
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  attacker: Ed25519Keypair;
  attackerAddress: string;
  admin: Ed25519Keypair;
  adminAddress: string;
  user: Ed25519Keypair;
  userAddress: string;
}

async function findMarketMaker(ctx: SetupContext): Promise<string> {
  const mmType = `${ctx.packageId}::market_maker::MarketMaker`;
  const marketMaker = (
    await ctx.chain.findCreatedObjects(ctx.adminAddress)
  ).find((object) => object.type === mmType);
  if (marketMaker) return marketMaker.id;
  throw new Error("setup: MarketMaker not found");
}

async function findAssetCoin(
  ctx: SetupContext,
  owner: string,
): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error(`setup: ${owner} holds no ASSET coin`);
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const mm = await findMarketMaker(ctx);

  // (1) admin funds the victim with D ASSET.
  const adminCoin = await findAssetCoin(ctx, ctx.adminAddress);
  const fund = new Transaction();
  fund.setSender(ctx.adminAddress);
  const [victimCoin] = fund.splitCoins(fund.object(adminCoin), [
    fund.pure.u64(VICTIM_DEPOSIT),
  ]);
  fund.transferObjects([victimCoin], ctx.userAddress);
  const fundRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: fund,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (fundRes.$kind === "FailedTransaction")
    throw new Error("setup: fund victim failed");
  await ctx.client.core.waitForTransaction({ result: fundRes });

  // (2) victim opens a market-maker account and deposits D collateral.
  const userCoin = await findAssetCoin(ctx, ctx.userAddress);
  const open = new Transaction();
  open.setSender(ctx.userAddress);
  open.moveCall({
    target: `${ctx.packageId}::market_maker::open_account`,
    arguments: [open.object(mm)],
  });
  open.moveCall({
    target: `${ctx.packageId}::market_maker::deposit`,
    arguments: [open.object(mm), open.object(userCoin)],
  });
  const openRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: open,
    signer: ctx.user,
    include: { effects: true },
  });
  if (openRes.$kind === "FailedTransaction")
    throw new Error("setup: victim open+deposit failed");
  await ctx.client.core.waitForTransaction({ result: openRes });
}
