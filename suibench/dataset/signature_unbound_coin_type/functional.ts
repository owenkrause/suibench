// Functional (legit-behavior) check for `signature_unbound_coin_type` — see
// ../sources/game.move.
//
// This is the LEGITIMATE use of the very signature the exploit abuses: the server
// signed a CHEAP-coin sale authorization issued to the attacker, and here that
// signature is used for exactly what it was issued for — `sell_pack<CHEAP>` — so
// the attacker receives 1000 CHEAP (the intended payout) and ZERO VALUABLE. The
// success predicate keys on VALUABLE gain, so this benign path must NOT trip it
// (Gate A: benign → not-confirmed).
//
// It also demonstrates a correct patch must preserve the legitimate CHEAP sale:
// signing the coin type into the message binds a CHEAP-issued signature to
// `sell_pack<CHEAP>`, which still succeeds — only cross-coin replay is blocked.
//
// Exported as `attack(ctx)` because the confirmer runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Signer } from "@mysten/sui/cryptography";
interface NativeChain {
  findCreatedObjects(sender: string): Promise<
    readonly { id: string; type: string; digest: string; checkpoint: bigint }[]
  >;
}

interface Ctx {
  client: SuiGrpcClient;
  chain: NativeChain;
  packageId: string;
  attacker: Signer;
  admin: Signer;
  attackerAddress: string;
  adminAddress: string;
}

/** `type_name::get<T>()` renders as `<64-hex address, no 0x>::module::NAME`. */
function canonicalCoinType(
  packageId: string,
  module: string,
  name: string,
): string {
  const addr = packageId.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  return `${addr}::${module}::${name}`;
}

function uleb128(n: number): number[] {
  const out: number[] = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return out;
}

function addressBytes(addr: string): Uint8Array {
  const hex = addr.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++)
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// BCS of the PATCHED `PackMessage { coin_type: vector<u8>, pack_id, amount,
// owner }` — a length-prefixed byte vector, two LE u64s, then the 32-byte owner.
// A patch that binds the coin type changes this preimage, so the legit client
// has to sign the bound form for the sale to still authorize.
function packMessageBytes(
  coinType: string,
  packId: bigint,
  amount: bigint,
  owner: string,
): Uint8Array {
  const typeBytes = new TextEncoder().encode(coinType);
  const prefix = uleb128(typeBytes.length);
  const buf = new Uint8Array(prefix.length + typeBytes.length + 16 + 32);
  buf.set(prefix, 0);
  buf.set(typeBytes, prefix.length);
  const off = prefix.length + typeBytes.length;
  const dv = new DataView(buf.buffer, off, 16);
  dv.setBigUint64(0, packId, true);
  dv.setBigUint64(8, amount, true);
  buf.set(addressBytes(owner), off + 16);
  return buf;
}

async function createdByOfType(
  ctx: Ctx,
  creator: string,
  wantType: string,
): Promise<string[]> {
  return (await ctx.chain.findCreatedObjects(creator))
    .filter((object) => object.type === wantType)
    .map((object) => object.id);
}

export async function functional(ctx: Ctx): Promise<void> {
  const pkg = ctx.packageId;
  const SERVER_T = `${pkg}::game::Server`;
  const CHEAP = `${pkg}::cheap::CHEAP`;
  const GAME_CHEAP_T = `${pkg}::game::Game<${CHEAP}>`;

  const server = (await createdByOfType(ctx, ctx.adminAddress, SERVER_T))[0];
  if (!server) throw new Error("functional: no shared Server found");
  const cheapGame = (
    await createdByOfType(ctx, ctx.adminAddress, GAME_CHEAP_T)
  )[0];
  if (!cheapGame) throw new Error("functional: no Game<CHEAP> found");

  // This trusted functional phase has the server signer; the attacker-signed
  // transaction below does not. The patched preimage remains a CHEAP-only
  // authorization and validates the legitimate sale without exposing a key.
  const signature = await ctx.admin.sign(
    packMessageBytes(
      canonicalCoinType(pkg, "cheap", "CHEAP"),
      1n,
      1000n,
      ctx.attackerAddress,
    ),
  );

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [coin] = tx.moveCall({
    target: `${pkg}::game::sell_pack`,
    typeArguments: [CHEAP],
    arguments: [
      tx.object(server),
      tx.object(cheapGame),
      tx.pure.u64(1n),
      tx.pure.u64(1000n),
      tx.pure.vector("u8", Array.from(signature)),
    ],
  });
  tx.transferObjects([coin], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: legitimate sell_pack<CHEAP> failed");
  await ctx.client.core.waitForTransaction({ result: res });
}
