// Functional (legit-behavior) check for `magna_vesting_div_by_zero` — see
// ../sources/vesting.move.
//
// Benign flow (Gate A anchor): the SAME create+withdraw path as the exploit, but with
// a WELL-FORMED allocation — a real linear-vesting schedule with non-zero divisors.
// The victim's withdraw then computes a genuine vested amount and SUCCEEDS, taking a
// non-zero coin. This proves V is denied by the bug (period_length == 0), not by the
// create/withdraw flow itself.
//
// Schedule: started ~100s ago, 10s periods, 10 periods, 1000 MIST total. By withdraw
// time ~10 periods have elapsed, so vested = 1000 * 10 / 10 = 1000 MIST (bounded well
// below the 1_000_000 MIST committed, so coin::take succeeds). start_time is set from
// wall-clock seconds so `final_ts - start_time` stays a small positive elapsed_time.
import { Transaction } from "@mysten/sui/transactions";

interface FunctionalContext {
  client: {
    core: {
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<unknown>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  userAddress: string;
}

const PERIOD_LENGTH = 10;
const NUMBER_OF_PERIODS = 10;
const AMOUNT = 1000n;
const FUNDS = 1_000_000;

function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}
function u64le(n: bigint): number[] {
  const o: number[] = [];
  let v = n;
  for (let i = 0; i < 8; i++) {
    o.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return o;
}
function encodePiece(startTime: number): number[] {
  return [
    ...u32le(startTime),
    ...u32le(PERIOD_LENGTH),
    ...u32le(NUMBER_OF_PERIODS),
    ...u64le(AMOUNT),
  ];
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  const startTime = Math.max(0, Math.floor(Date.now() / 1000) - 100);
  const alloc = encodePiece(startTime);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);
  const [funds] = tx.splitCoins(tx.gas, [FUNDS]);
  tx.moveCall({
    target: `${ctx.packageId}::vesting::create`,
    arguments: [
      funds,
      tx.pure.address(ctx.userAddress),
      tx.pure.vector("u8", alloc),
    ],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

/** Readable alias — the confirmer runner only ever calls `attack`. */
export const functional = attack;
