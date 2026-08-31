// Benign functional path for `withdraw_penalty_not_withheld` — see
// ../sources/liquidity_provider.move.
//
// The legitimate LP flow: deposit 50000, then withdraw exactly the 50000
// principal. A fair withdrawal takes back only what was deposited — no skim
// of the pool's other capital — so the attacker's net over their own stake is
// 0 (buggy contract) or -2500 (correct contract, penalty withheld). This is a
// compile/non-abort control: its event is not supplied as attack evidence to
// `check.ts` during gold-patch verification.
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
  const type = `${ctx.packageId}::liquidity_provider::Pool`;
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
  const [stake] = tx.splitCoins(tx.object(coin), [tx.pure.u64(50000)]);
  tx.moveCall({
    target: `${ctx.packageId}::liquidity_provider::deposit`,
    arguments: [tx.object(pool), stake],
  });
  const out = tx.moveCall({
    target: `${ctx.packageId}::liquidity_provider::withdraw`,
    arguments: [tx.object(pool), tx.pure.u64(50000)],
  });
  tx.transferObjects([out], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}
