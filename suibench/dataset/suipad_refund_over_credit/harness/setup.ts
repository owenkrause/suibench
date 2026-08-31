// Setup for the `suipad_refund_over_credit` entry — seeds the vault before the
// attack, then the pre-snapshot is taken.
//
// The package's `token` module `init` mints the full fixed supply of 1,000,000
// TOKEN to the deployer (admin) and freezes the treasury cap, so TOKEN supply is
// permanently fixed at 1,000,000 and no more can ever be minted. Here the ADMIN:
//   1. splits 100,000 TOKEN off its coin and calls `vault::open`, creating the
//      shared Vault seeded with 100,000 TOKEN of investment liquidity, and
//   2. splits 100 TOKEN off and transfers it to the ATTACKER — the attacker's
//      stake to invest (exactly the position a normal user would hold).
// After setup: a shared Vault holding 100,000 TOKEN, the attacker holding 100
// TOKEN, and the admin holding the remaining ~899,900 TOKEN. The checker does
// not infer exploitation from these aggregate balances: it requires a
// successful attacker-authored `RefundClaimed` event whose paid amount exceeds
// the deposited amount (see ./check.ts).
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
}

async function findAdminTokenCoin(ctx: SetupContext): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>`,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error("setup: admin holds no TOKEN coin");
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const coinId = await findAdminTokenCoin(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);

  // Split the vault seed (100,000) and the attacker's stake (100) off the
  // admin's TOKEN coin.
  const [seedCoin, stakeCoin] = tx.splitCoins(tx.object(coinId), [
    tx.pure.u64(100000),
    tx.pure.u64(100),
  ]);

  // Seed the shared Vault with 100,000 TOKEN.
  tx.moveCall({
    target: `${ctx.packageId}::vault::open`,
    arguments: [seedCoin],
  });

  // Hand the attacker their 100 TOKEN stake.
  tx.transferObjects([stakeCoin], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
