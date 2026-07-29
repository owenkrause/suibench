// Functional (legit-behavior) check for `signature_unbound_coin_type` — see
// ../sources/game.move.
//
// This is the LEGITIMATE use of the very signature the exploit abuses: the server
// signed PackMessage{1,1000,1} to authorize a CHEAP-coin sale, and here that
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
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface ObjectChange {
  type: string;
  objectType?: string;
  objectId?: string;
}

interface Ctx {
  client: {
    queryTransactionBlocks(i: {
      filter?: unknown;
      options?: unknown;
      cursor?: string | null;
    }): Promise<{
      data: { objectChanges?: ObjectChange[] | null }[];
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
  adminAddress: string;
}

// Must match harness/setup.ts exactly.
const SERVER_SECRET = new Uint8Array(32).fill(7);

function packMessageBytes(
  packId: bigint,
  amount: bigint,
  nonce: bigint,
): Uint8Array {
  const buf = new Uint8Array(24);
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(0, packId, true);
  dv.setBigUint64(8, amount, true);
  dv.setBigUint64(16, nonce, true);
  return buf;
}

async function createdByOfType(
  ctx: Ctx,
  creator: string,
  wantType: string,
): Promise<string[]> {
  const ids: string[] = [];
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: creator },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const t of page.data)
      for (const c of t.objectChanges ?? []) {
        if (c.type === "created" && c.objectType === wantType && c.objectId)
          ids.push(c.objectId);
      }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  return ids;
}

export async function attack(ctx: Ctx): Promise<void> {
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

  const key = Ed25519Keypair.fromSecretKey(SERVER_SECRET);
  const signature = await key.sign(packMessageBytes(1n, 1000n, 1n));

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
      tx.pure.u64(1n),
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

export const functional = attack;
