import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
  readonly digest: string;
  readonly checkpoint: bigint;
}

interface FunctionalContext {
  client: {
    core: {
      signAndExecuteTransaction(input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }): Promise<unknown>;
      waitForTransaction(input: { result: unknown }): Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  adminAddress: string;
  attackerAddress: string;
  attacker: unknown;
}

// Benign flow: the SAME legitimate inserts as the attack, but WITHOUT the trap
// removals — a normal order book being populated. The tree stays well-formed
// (every live internal index < table::length), so the victim's next_leaf(32)
// traversal completes normally => the victim op succeeds => NOT confirmed. This
// is the Gate A anchor: the exploit is the deletion trap, not the inserts.
const INSERT_KEYS = [1, 2, 4, 8, 16, 32];

async function findShared(
  ctx: FunctionalContext,
  needle: string,
): Promise<string> {
  const object = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (created) => created.type.includes(needle),
  );
  if (object) return object.id;
  throw new Error(`functional: shared object matching ${needle} not found`);
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const holder = await findShared(ctx, "::critbit_test::TreeHolder");

  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  for (const k of INSERT_KEYS) {
    tx.moveCall({
      target: `${ctx.packageId}::critbit_test::insert`,
      arguments: [tx.object(holder), tx.pure.u64(String(k))],
    });
  }
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}
