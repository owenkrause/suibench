// Benign functional path for `unsegregated_protocol_fee` — see ../sources/amm_pool.move.
//
// The attacker adds a tiny 10 ASSET of liquidity and immediately removes it.
// On the gold patch this redeems exactly its fee-excluded LP basis (10), while
// retaining the ordinary add/remove path that the patch must preserve.
//
// This file exports `attack(ctx)` — the same AttackContext shape the
// confirmer's in-container runner (src/confirmer/runner.ts) invokes — so the
// existing container plumbing runs it unchanged. `functional` is exported as
// an alias for readability at the call site; the runner only ever calls
// `attack`.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Signer } from "@mysten/sui/cryptography";
interface NativeChain {
  findCreatedObjects(sender: string): Promise<
    readonly { id: string; type: string; digest: string; checkpoint: bigint }[]
  >;
}


interface FunctionalContext {
  client: SuiGrpcClient;
  chain: NativeChain;
  packageId: string;
  attacker: Signer;
  attackerAddress: string;
  adminAddress: string;
}

async function findPool(ctx: FunctionalContext): Promise<string> {
  const type = `${ctx.packageId}::amm_pool::Pool`;
  const created = await ctx.chain.findCreatedObjects(ctx.adminAddress);
  for (const object of created) {
    if (object.type === type) return object.id;
  }
  throw new Error("functional: Pool not found");
}
async function findCoin(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no ASSET");
  return id;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const pool = await findPool(ctx);
  const coin = await findCoin(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [deposit] = tx.splitCoins(tx.object(coin), [tx.pure.u64(10)]);
  tx.moveCall({
    target: `${ctx.packageId}::amm_pool::add_liquidity`,
    arguments: [tx.object(pool), deposit],
  });
  const payout = tx.moveCall({
    target: `${ctx.packageId}::amm_pool::remove_liquidity`,
    arguments: [tx.object(pool), tx.pure.u64(10)],
  });
  tx.transferObjects([payout], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}
