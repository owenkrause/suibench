import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface VictimContext {
  client: {
    core: {
      signAndExecuteTransaction(input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }): Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  attackerAddress: string;
  adminAddress: string;
  user: unknown;
  userAddress: string;
}

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
// attack script holds. Chain discovery covers each sender's created objects, so
// a null result means no such Vesting exists (an incomplete or failed exploit).
async function findVesting(ctx: VictimContext): Promise<string | null> {
  const type = `${ctx.packageId}::vesting::Vesting`;
  for (const from of [ctx.attackerAddress, ctx.adminAddress, ctx.userAddress]) {
    const vesting = (await ctx.chain.findCreatedObjects(from)).find(
      (object) => object.type === type,
    );
    if (vesting) return vesting.id;
  }
  return null;
}

export async function victim(ctx: VictimContext): Promise<unknown> {
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
    Number(process.env.SUIXPLOIT_VICTIM_GAS_BUDGET ?? "50000000"),
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
