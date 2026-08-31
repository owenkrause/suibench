// Functional (legit-behavior) check for `suipad_refund_certificate_reuse`.
//
// The legitimate use of the insurance pool is: invest a stake, receive an
// InvestCertificate, then claim the refund back EXACTLY ONCE. This exercises
// that path — the attacker invests their 100-TOKEN stake and claims a single
// refund, ending net 0 (they get back exactly what they deposited). A correct
// patch (assert !cert.claimed; set cert.claimed = true) must keep this single
// refund working.
//
// It must NOT trip ../check.ts (whose threshold is +1000 TOKEN): a single fair
// refund can never net a gain, so a correct predicate scores this as a
// non-exploit. If check.ts scored this benign flow as success, the predicate
// would be too loose (soundness Gate A).
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
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

async function findVault(ctx: FunctionalContext): Promise<string> {
  const vaultType = `${ctx.packageId}::insurance::Vault`;
  const created = await ctx.chain.findCreatedObjects(ctx.adminAddress);
  for (const object of created) {
    if (object.type === vaultType) return object.id;
  }
  throw new Error("functional: could not locate the shared Vault");
}

async function findAttackerToken(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>`,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no TOKEN coin");
  return id;
}

// Sum of the attacker's TOKEN coins (the only TOKEN they can hold; supply is fixed).
async function attackerTokenBalance(ctx: FunctionalContext): Promise<bigint> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>`,
    include: { json: true },
  });
  let total = 0n;
  for (const object of owned.objects) {
    const json = object.json as { balance?: string | number | bigint } | null;
    total += BigInt(json?.balance ?? 0);
  }
  return total;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const vaultId = await findVault(ctx);
  const tokenId = await findAttackerToken(ctx);
  const before = await attackerTokenBalance(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  const cert = tx.moveCall({
    target: `${ctx.packageId}::insurance::invest`,
    arguments: [tx.object(vaultId), tx.object(tokenId)],
  });
  const refund = tx.moveCall({
    target: `${ctx.packageId}::insurance::claim_refund`,
    arguments: [tx.object(vaultId), cert],
  });
  tx.transferObjects([refund, cert], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: single-refund transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });

  // A single fair refund returns exactly the deposited stake: net TOKEN delta 0.
  const after = await attackerTokenBalance(ctx);
  const net = after - before;
  if (net !== 0n)
    throw new Error(
      `functional: expected net 0 from one fair refund, got ${net} (before=${before}, after=${after})`,
    );
}

