// Functional (legit-behavior) check for `movectf2024_swap_flashloan`.
//
// The legitimate use of the pool is a plain swap: a user trades some COINA for
// COINB at the current price, with no flash loan. This exercises exactly that —
// the attacker swaps their own 10 COINA against the unskewed 100/100 pool,
// receiving ~10 COINB (Δ +10). A correct constant-product patch must keep this
// path working. It must NOT trip ./check.ts (whose threshold is +90 COINB): a
// fair swap can never capture the pool, so a correct predicate scores this as a
// non-exploit. If check.ts scored this benign flow as success, the predicate
// would be too loose (soundness Gate A).
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface FunctionalContext {
  client: {
    core: {
      listOwnedObjects(input: {
        owner: string;
        type?: string;
        include?: { json?: boolean };
      }): Promise<{
        objects: { objectId: string; type: string; json?: unknown }[];
      }>;
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
}

async function findVault(ctx: FunctionalContext): Promise<string> {
  const vaultPrefix = `${ctx.packageId}::vault::Vault<`;
  const vault = (await ctx.chain.findCreatedObjects(ctx.attackerAddress)).find(
    (object) => object.type.startsWith(vaultPrefix),
  );
  if (vault) return vault.id;
  throw new Error("functional: could not locate the shared Vault");
}

async function findAttackerCoinA(ctx: FunctionalContext): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::coina::COINA>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no COINA coin");
  return id;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const TA = `${ctx.packageId}::coina::COINA`;
  const TB = `${ctx.packageId}::coinb::COINB`;
  const vaultId = await findVault(ctx);
  const coinAId = await findAttackerCoinA(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const outB = tx.moveCall({
    target: `${ctx.packageId}::vault::swap_a_to_b`,
    typeArguments: [TA, TB],
    arguments: [tx.object(vaultId), tx.object(coinAId)],
  });
  tx.transferObjects([outB], ctx.attackerAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: swap transaction failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

