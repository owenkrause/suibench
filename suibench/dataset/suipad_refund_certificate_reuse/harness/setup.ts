// Setup for the `suipad_refund_certificate_reuse` entry — seeds the insurance
// pool before the attack, then the pre-snapshot is taken.
//
// The package publishes one coin module whose `init` mints 1000000 TOKEN to the
// deployer (admin) and freezes both metadata and the treasury cap, so TOKEN
// total supply is permanently fixed at 1000000. In setup the ADMIN:
//   1. splits ~100000 TOKEN and calls `insurance::open(coin)`, which shares a
//      `Vault` funded with that 100000 (the insurance reserve), and
//   2. splits ~100 TOKEN and transfers it to the ATTACKER (their stake — exactly
//      the position a normal investor would have).
// After setup: a shared Vault holding 100000 TOKEN, and the attacker holding 100
// TOKEN. Supply is fixed, so the attacker's 100 stake is the ONLY TOKEN they can
// legitimately account for; any TOKEN they end with beyond a single refunded
// deposit must have come out of the shared reserve (see ./check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiJsonRpcClient & {
    getOwnedObjects(input: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
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
  attacker: Ed25519Keypair;
  attackerAddress: string;
  admin: Ed25519Keypair;
  adminAddress: string;
}

async function findAdminToken(ctx: SetupContext): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error("setup: admin holds no TOKEN coin");
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const tokenId = await findAdminToken(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  // Seed the insurance Vault with 100000 TOKEN, and hand the attacker a 100 TOKEN stake.
  const [seed] = tx.splitCoins(tx.object(tokenId), [tx.pure.u64(100000)]);
  tx.moveCall({
    target: `${ctx.packageId}::insurance::open`,
    arguments: [seed],
  });
  const [stake] = tx.splitCoins(tx.object(tokenId), [tx.pure.u64(100)]);
  tx.transferObjects([stake], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: seed transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
