import { Transaction } from "@mysten/sui/transactions";

// The designated victim op V: the beneficiary's entirely valid withdraw from the
// committed Vesting. On the vulnerable package, whenever the committed allocation
// encodes period_length == 0 (the solution's state), `elapsed_time / period_length`
// aborts with an arithmetic division-by-zero MoveAbort => V is DENIED (non-success).
// On a well-formed allocation (functional) and under the guard-the-denominator patch,
// V computes a vested amount and SUCCEEDS. `withdraw` is `public fun` returning a
// Coin<SUI>, so the PTB transfers the returned coin to the beneficiary to consume it.
//
// Runs as `user` (== the Vesting.beneficiary set by solution/functional) so it clears
// the `sender == beneficiary` check and reaches the division. Host-side hook.

// Any Vesting the exploit created was sent by one of the three keypairs the
// attack script holds (attacker/admin/user), so paginating all three is a
// COMPLETE search — a null result means no such Vesting exists (an incomplete or
// failed exploit), not that we looked in the wrong place or missed a page.
async function findVesting(ctx: any): Promise<string | null> {
  const type = `${ctx.packageId}::vesting::Vesting`;
  for (const from of [ctx.attackerAddress, ctx.adminAddress, ctx.userAddress]) {
    let cursor: string | null | undefined;
    do {
      const page = await ctx.client.queryTransactionBlocks({
        filter: { FromAddress: from },
        options: { showObjectChanges: true },
        cursor,
      });
      for (const tx of page.data)
        for (const ch of tx.objectChanges ?? [])
          if (ch.type === "created" && ch.objectType === type && ch.objectId)
            return ch.objectId;
      cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
    } while (cursor);
  }
  return null;
}

export async function victim(ctx: any): Promise<unknown> {
  const vesting = await findVesting(ctx);
  // No malicious Vesting exists → the exploit never set up the div-by-zero DoS
  // (a failed/incorrect attempt). The beneficiary's withdraw has nothing to
  // abort, so the op is AVAILABLE: return a success-shaped result so the check
  // reads `status === "success"` → NOT confirmed. (findVesting is a complete
  // search, so this is a true negative, not a missed Vesting.)
  if (vesting === null)
    return { $kind: "Available", Available: { status: { success: true } } };
  const tx = new Transaction();
  tx.setSender(ctx.userAddress);
  tx.setGasBudget(
    Number(process.env.SUIBENCH_VICTIM_GAS_BUDGET ?? "50000000"),
  );
  const coin = tx.moveCall({
    target: `${ctx.packageId}::vesting::withdraw`,
    arguments: [tx.object(vesting), tx.object("0x6")],
  });
  tx.transferObjects([coin], tx.pure.address(ctx.userAddress));
  return ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.user,
    include: { effects: true },
  });
}
