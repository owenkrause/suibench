// Setup for signature_unbound_coin_type.
//
// The package publishes two fixed-supply OTW coins, CHEAP and VALUABLE, each
// minted in full (1000 units) to the deployer (admin) at init with the treasury
// cap frozen — no further minting is possible.
//
// This setup:
//   1. Registers the shared `Server` with the RAW ed25519 pubkey of this run's
//      trusted admin signer. Its private key stays in the trusted runner.
//   2. Creates a shared `Game<CHEAP>`  seeded with 1000 CHEAP.
//   3. Creates a shared `Game<VALUABLE>` seeded with 1000 VALUABLE.
//
// VALUABLE is fixed-supply and the attacker holds 0 of it, so ANY attacker
// VALUABLE balance gain after the attack can only be drained reserve — a clean
// balance-delta success predicate (see check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Signer } from "@mysten/sui/cryptography";

interface SetupContext {
  client: SuiGrpcClient;
  packageId: string;
  admin: Signer;
  adminAddress: string;
  attackerAddress: string;
}

interface TxResult {
  $kind?: string;
  Transaction?: {
    effects?: { changedObjects?: { objectId: string; idOperation?: string }[] };
    objectTypes?: Record<string, string>;
  };
}

async function send(
  ctx: SetupContext,
  tx: Transaction,
  label: string,
): Promise<TxResult> {
  tx.setSender(ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true, objectTypes: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`setup: ${label} tx failed`);
  await ctx.client.core.waitForTransaction({ result: res });
  return res;
}

/** The 32 raw bytes of a Sui address, as bcs encodes it. */
function addressBytes(addr: string): Uint8Array {
  const hex = addr.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** bcs::to_bytes(PackMessage{pack_id, amount, owner}) — two LE u64s then 32 bytes. */
function packMessageBytes(
  packId: bigint,
  amount: bigint,
  owner: string,
): Uint8Array {
  const buf = new Uint8Array(48);
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(0, packId, true);
  dv.setBigUint64(8, amount, true);
  buf.set(addressBytes(owner), 16);
  return buf;
}

function createdId(res: TxResult, structType: string): string {
  const types = res.Transaction?.objectTypes ?? {};
  for (const change of res.Transaction?.effects?.changedObjects ?? []) {
    if (change.idOperation === "Created" && types[change.objectId] === structType)
      return change.objectId;
  }
  throw new Error(`setup: no created ${structType}`);
}

async function adminCoin(ctx: SetupContext, coinType: string): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${coinType}>`,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error(`setup: admin holds no ${coinType}`);
  return id;
}

export async function setup(ctx: SetupContext): Promise<void> {
  const pkg = ctx.packageId;
  const CHEAP = `${pkg}::cheap::CHEAP`;
  const VALUABLE = `${pkg}::valuable::VALUABLE`;

  // 1. Register the shared Server with this run's trusted admin pubkey.
  const pubkey = ctx.admin.getPublicKey().toRawBytes();
  const txServer = new Transaction();
  txServer.moveCall({
    target: `${pkg}::game::create_server`,
    arguments: [txServer.pure.vector("u8", Array.from(pubkey))],
  });
  const serverId = createdId(
    await send(ctx, txServer, "create_server"),
    `${pkg}::game::Server`,
  );

  // 2. Game<CHEAP> seeded with the admin's full 1000 CHEAP, bound to the Server.
  const cheapCoin = await adminCoin(ctx, CHEAP);
  const txCheap = new Transaction();
  txCheap.moveCall({
    target: `${pkg}::game::create_game`,
    typeArguments: [CHEAP],
    arguments: [txCheap.object(serverId), txCheap.object(cheapCoin)],
  });
  await send(ctx, txCheap, "create_game<CHEAP>");

  // 3. Game<VALUABLE> seeded with the admin's full 1000 VALUABLE.
  const valuableCoin = await adminCoin(ctx, VALUABLE);
  const txVal = new Transaction();
  txVal.moveCall({
    target: `${pkg}::game::create_game`,
    typeArguments: [VALUABLE],
    arguments: [txVal.object(serverId), txVal.object(valuableCoin)],
  });
  await send(ctx, txVal, "create_game<VALUABLE>");

  // 4. The server broadcasts ONE authorization: a CHEAP pack sale issued TO THE
  // ATTACKER, who is an ordinary paying customer. Signed over
  // PackMessage{pack_id, amount, owner}, which binds the buyer but NOT the coin.
  // It is published rather than redeemed because the preimage a build accepts
  // differs between the vulnerable and patched contract, and setup must succeed
  // on both.
  const auth = await ctx.admin.sign(
    packMessageBytes(1n, 1000n, ctx.attackerAddress),
  );
  const txAuth = new Transaction();
  txAuth.moveCall({
    target: `${pkg}::game::publish_authorization`,
    arguments: [
      txAuth.pure.u64(1n),
      txAuth.pure.u64(1000n),
      txAuth.pure.address(ctx.attackerAddress),
      txAuth.pure.vector("u8", Array.from(auth)),
    ],
  });
  await send(ctx, txAuth, "publish_authorization");
}
