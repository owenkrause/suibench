// Setup for the `unchecked_arithmetic` entry — seeds state before the attack,
// then the pre-snapshot is taken.
//
// The package's `asset` module `init` mints the full fixed supply of 1,000,000
// ASSET to the deployer (admin) and freezes the treasury cap, so ASSET supply is
// permanently fixed at 1,000,000 and no more can ever be minted. The
// `reward_pool` module `init` shares an empty RewardPool and hands the deployer
// the sole PoolAdmin cap. Since the container publishes as ADMIN, both the full
// ASSET supply and the PoolAdmin cap start with the admin.
//
// The exploit assumes the ATTACKER holds the PoolAdmin cap (to donate rewards)
// and is the first depositor, while a DIFFERENT victim later deposits a normal
// amount. So the admin here:
//   1. transfers the PoolAdmin cap to the ATTACKER,
//   2. funds the ATTACKER with 100,001 ASSET (1 for the tiny first deposit +
//      100,000 to donate via add_rewards), and
//   3. seeds the VICTIM (user) with exactly D = 100,000 liquid ASSET — the
//      normal-sized deposit the attacker will capture.
// All deposits / the donation / the victim deposit / the withdraw happen INSIDE
// the attack scripts, so the pre-snapshot captures full liquid balances and the
// check measures true NET profit. The fixed supply is what makes the check's
// "attacker captured the victim's deposit" predicate sound (see ./check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

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

async function findAdminObject(
  ctx: SetupContext,
  structType: string,
  label: string,
): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: structType,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error(`setup: admin holds no ${label}`);
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const coinId = await findAdminObject(
    ctx,
    `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    "ASSET coin",
  );
  const adminCapId = await findAdminObject(
    ctx,
    `${ctx.packageId}::reward_pool::PoolAdmin`,
    "PoolAdmin cap",
  );

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);

  // Split the attacker's stake (100,001 = 1 first-deposit + 100,000 donation)
  // and the victim's deposit (100,000) off the admin's ASSET coin.
  const [attackerStake, victimDeposit] = tx.splitCoins(tx.object(coinId), [
    tx.pure.u64(100001),
    tx.pure.u64(100000),
  ]);

  // Route the PoolAdmin cap to the attacker so they can donate via add_rewards.
  tx.transferObjects([tx.object(adminCapId)], ctx.attackerAddress);
  // Fund the attacker and the victim with their liquid ASSET.
  tx.transferObjects([attackerStake], ctx.attackerAddress);
  tx.transferObjects([victimDeposit], ctx.userAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
