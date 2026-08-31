// Functional (legit-behavior) check for `suipad_refund_over_credit`.
//
// The legitimate flow is a full round-trip: a user `invest`s their TOKEN and
// then `claim_refund`s to get it back. This exercises exactly that — the
// attacker invests their 100 TOKEN stake, claims the refund, and we assert the
// NET outcome is FAIR: they end holding exactly their stake back (net 0), the
// value a correctly-patched claim_refund returns.
//
// This runs only on the PATCHED build. Asserting the repaired VALUE is what
// closes the S6 hole: a patch that merely disables claim_refund fails here (the
// claim tx aborts), and a patch that still over-credits fails here too (the
// attacker would hold 1000x the stake, not the stake). A deposit-only check
// could not tell any of these apart.
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


const STAKE = 100n; // attacker's TOKEN stake, seeded by ./harness/setup.ts

interface FunctionalContext {
  client: SuiGrpcClient;
  chain: NativeChain;
  packageId: string;
  attacker: Signer;
  attackerAddress: string;
  adminAddress: string;
}

async function findVault(ctx: FunctionalContext): Promise<string> {
  const vaultType = `${ctx.packageId}::vault::Vault`;
  const created = await ctx.chain.findCreatedObjects(ctx.adminAddress);
  for (const object of created) {
    if (object.type === vaultType) return object.id;
  }
  throw new Error("functional: could not locate the shared Vault");
}

async function findAttackerTokenCoin(ctx: FunctionalContext): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>`,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no TOKEN coin");
  return id;
}

/** Sum the attacker's TOKEN coin balances (TOKEN is not the gas coin). */
async function attackerTokenTotal(ctx: FunctionalContext): Promise<bigint> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>`,
    include: { json: true },
  });
  let total = 0n;
  for (const o of owned.objects) {
    const json = o.json as { balance?: string | number | bigint } | null;
    const bal = json?.balance;
    if (bal !== undefined) total += BigInt(bal);
  }
  return total;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const vaultId = await findVault(ctx);
  const coinId = await findAttackerTokenCoin(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  // Round-trip: invest the 100 TOKEN stake, then claim the refund back.
  const ticket = tx.moveCall({
    target: `${ctx.packageId}::vault::invest`,
    arguments: [tx.object(vaultId), tx.object(coinId)],
  });
  const refund = tx.moveCall({
    target: `${ctx.packageId}::vault::claim_refund`,
    arguments: [tx.object(vaultId), ticket],
  });
  tx.transferObjects([refund], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: invest -> claim_refund transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });

  // A fair refund returns exactly the stake, so the attacker's total TOKEN
  // holding after the round-trip is exactly the stake (net 0). Anything else —
  // the 1000x over-credit, or a claim that silently paid nothing — is a failure.
  const total = await attackerTokenTotal(ctx);
  if (total !== STAKE)
    throw new Error(
      `functional: expected a fair refund (total ${STAKE} TOKEN), got ${total}`,
    );
}

