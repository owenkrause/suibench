import { Transaction } from "@mysten/sui/transactions";

// Benign flow: the SAME legitimate inserts as the attack, but WITHOUT the trap
// removals — a normal order book being populated. The tree stays well-formed
// (every live internal index < table::length), so the victim's next_leaf(32)
// traversal completes normally => the victim op succeeds => NOT confirmed. This
// is the Gate A anchor: the exploit is the deletion trap, not the inserts.
const INSERT_KEYS = [1, 2, 4, 8, 16, 32];

async function findShared(ctx: any, needle: string): Promise<string> {
  const page = await ctx.client.queryTransactionBlocks({
    filter: { FromAddress: ctx.adminAddress },
    options: { showObjectChanges: true },
  });
  for (const tx of page.data)
    for (const ch of tx.objectChanges ?? [])
      if (
        ch.type === "created" &&
        typeof ch.objectType === "string" &&
        ch.objectType.includes(needle) &&
        ch.objectId
      )
        return ch.objectId;
  throw new Error(`functional: shared object matching ${needle} not found`);
}

export async function attack(ctx: any): Promise<void> {
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
