// Setup for the `navi_supply_balance_public` entry — seeds the storage reserve
// before the attack, then the pre-snapshot is taken.
//
// The package's `token` module `init` mints a fixed 1_000_000 TOKEN supply to the
// deployer (admin) and then FREEZES both the metadata and the treasury cap, so no
// more TOKEN can ever be minted — total supply is permanently pinned to that
// initial mint. As ADMIN we split 1000 TOKEN off the deployer's coin and call
// `storage::open`, creating a shared Storage holding a 1000-TOKEN reserve and an
// EMPTY supply table. The attacker holds ZERO TOKEN after setup and has no supply
// balance recorded. This fixed-supply / zero-attacker starting position is what
// makes the check's "attacker drained the reserve" predicate sound (see ./check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiGrpcClient & {
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
  admin: Ed25519Keypair;
  attacker: Ed25519Keypair;
  attackerAddress: string;
  adminAddress: string;
}

// The admin (deployer) received the full 1_000_000 TOKEN supply in the token
// module's `init`. Find that coin object by its owned StructType.
async function findAdminToken(ctx: SetupContext): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("setup: admin holds no TOKEN coin");
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const tokenId = await findAdminToken(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);
  const [reserveCoin] = tx.splitCoins(tx.object(tokenId), [tx.pure.u64(1000)]);
  tx.moveCall({
    target: `${ctx.packageId}::storage::open`,
    arguments: [reserveCoin],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("setup: storage::open transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
