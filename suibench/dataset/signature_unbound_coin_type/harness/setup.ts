// Setup for signature_unbound_coin_type.
//
// The package publishes two fixed-supply OTW coins, CHEAP and VALUABLE, each
// minted in full (1000 units) to the deployer (admin) at init with the treasury
// cap frozen — no further minting is possible.
//
// This setup:
//   1. Registers the shared `Server` with the RAW ed25519 pubkey of a FIXED
//      server keypair (derived from a fixed 32-byte secret, so solution.mts /
//      functional.mts can reconstruct the same key and re-sign the message).
//   2. Creates a shared `Game<CHEAP>`  seeded with 1000 CHEAP.
//   3. Creates a shared `Game<VALUABLE>` seeded with 1000 VALUABLE.
//
// VALUABLE is fixed-supply and the attacker holds 0 of it, so ANY attacker
// VALUABLE balance gain after the attack can only be drained reserve — a clean
// balance-delta success predicate (see check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiJsonRpcClient & {
    getOwnedObjects(input: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
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
  admin: Ed25519Keypair;
  adminAddress: string;
  attackerAddress: string;
}

// FIXED server secret — shared verbatim with solution.mts / functional.mts so
// they can reconstruct the exact same keypair and produce a signature that
// verifies against the pubkey registered here. `fromSecretKey` accepts a raw
// 32-byte Uint8Array.
const SERVER_SECRET = new Uint8Array(32).fill(7);

async function send(
  ctx: SetupContext,
  tx: Transaction,
  label: string,
): Promise<void> {
  tx.setSender(ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`setup: ${label} tx failed`);
  await ctx.client.core.waitForTransaction({ result: res });
}

async function adminCoin(ctx: SetupContext, coinType: string): Promise<string> {
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `0x2::coin::Coin<${coinType}>` },
    options: { showType: true },
  });
  const id = owned.data[0]?.data?.objectId;
  if (!id) throw new Error(`setup: admin holds no ${coinType}`);
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const pkg = ctx.packageId;
  const CHEAP = `${pkg}::cheap::CHEAP`;
  const VALUABLE = `${pkg}::valuable::VALUABLE`;

  // 1. Register the shared Server with the fixed key's RAW 32-byte pubkey.
  const server = Ed25519Keypair.fromSecretKey(SERVER_SECRET);
  const pubkey = server.getPublicKey().toRawBytes();
  const txServer = new Transaction();
  txServer.moveCall({
    target: `${pkg}::game::create_server`,
    arguments: [txServer.pure.vector("u8", Array.from(pubkey))],
  });
  await send(ctx, txServer, "create_server");

  // 2. Game<CHEAP> seeded with the admin's full 1000 CHEAP.
  const cheapCoin = await adminCoin(ctx, CHEAP);
  const txCheap = new Transaction();
  txCheap.moveCall({
    target: `${pkg}::game::create_game`,
    typeArguments: [CHEAP],
    arguments: [txCheap.object(cheapCoin)],
  });
  await send(ctx, txCheap, "create_game<CHEAP>");

  // 3. Game<VALUABLE> seeded with the admin's full 1000 VALUABLE.
  const valuableCoin = await adminCoin(ctx, VALUABLE);
  const txVal = new Transaction();
  txVal.moveCall({
    target: `${pkg}::game::create_game`,
    typeArguments: [VALUABLE],
    arguments: [txVal.object(valuableCoin)],
  });
  await send(ctx, txVal, "create_game<VALUABLE>");
}
