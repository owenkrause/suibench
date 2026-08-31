// Functional (legit-behavior) check for `unchecked_arithmetic`.
//
// The legitimate flow is two normal-sized deposits into the reward pool. Here the
// attacker (first depositor) deposits their liquid ASSET and the VICTIM then
// deposits their D = 100,000 ASSET — a normal amount, with NO donation inflating
// the pool. Under correct-sized deposits `deposit` mints proportional, NONZERO
// shares to both, and the attacker then withdraws roughly what they put in
// (net ~0). Because there is no share-inflation donation:
//   - the victim receives NONZERO shares (clause 2 of ./check.ts fails), and
//   - the attacker nets ~0 ASSET (clause 1 fails).
// So this benign path must NOT trip ./check.ts. It exercises the honest deposit /
// withdraw path end-to-end without the attacker donating to inflate pool.balance.
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
  admin: Signer;
  adminAddress: string;
  user: Signer;
  userAddress: string;
}

async function findPool(ctx: FunctionalContext): Promise<string> {
  const poolType = `${ctx.packageId}::reward_pool::RewardPool`;
  const created = await ctx.chain.findCreatedObjects(ctx.adminAddress);
  for (const object of created) {
    if (object.type === poolType) return object.id;
  }
  throw new Error("functional: could not locate the shared RewardPool");
}

async function findOne(
  ctx: FunctionalContext,
  owner: string,
  structType: string,
  label: string,
): Promise<string> {
  const owned = await ctx.client.core.listOwnedObjects({
    owner: owner,
    type: structType,
  });
  const id = owned.objects[0]?.objectId;
  if (!id) throw new Error(`functional: ${label} not found`);
  return id;
}

async function run(
  ctx: FunctionalContext,
  signer: Signer,
  build: (tx: Transaction) => void,
  sender: string,
  what: string,
) {
  const tx = new Transaction();
  tx.setSender(sender);
  build(tx);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`functional: ${what} failed`);
  await ctx.client.core.waitForTransaction({ result: res });
}

const COIN = (ctx: FunctionalContext) =>
  `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`;

export async function functional(ctx: FunctionalContext): Promise<void> {
  const poolId = await findPool(ctx);

  // 1) attacker (first depositor): deposit 100,000 ASSET -> nonzero shares.
  const attackerCoin = await findOne(
    ctx,
    ctx.attackerAddress,
    COIN(ctx),
    "attacker ASSET coin",
  );
  await run(
    ctx,
    ctx.attacker,
    (tx) => {
      const [stake] = tx.splitCoins(tx.object(attackerCoin), [
        tx.pure.u64(100000),
      ]);
      const share = tx.moveCall({
        target: `${ctx.packageId}::reward_pool::deposit`,
        arguments: [tx.object(poolId), stake],
      });
      tx.transferObjects([share], ctx.attackerAddress);
    },
    ctx.attackerAddress,
    "attacker deposit",
  );

  // 2) VICTIM: deposit their 100,000 ASSET -> proportional NONZERO shares.
  const victimCoin = await findOne(
    ctx,
    ctx.userAddress,
    COIN(ctx),
    "victim ASSET coin",
  );
  await run(
    ctx,
    ctx.user,
    (tx) => {
      const share = tx.moveCall({
        target: `${ctx.packageId}::reward_pool::deposit`,
        arguments: [tx.object(poolId), tx.object(victimCoin)],
      });
      tx.transferObjects([share], ctx.userAddress);
    },
    ctx.userAddress,
    "victim deposit",
  );

  // 3) attacker: withdraw their shares -> gets ~their deposit back (net ~0).
  const shareId = await findOne(
    ctx,
    ctx.attackerAddress,
    `${ctx.packageId}::reward_pool::ShareToken`,
    "attacker ShareToken",
  );
  await run(
    ctx,
    ctx.attacker,
    (tx) => {
      const coin = tx.moveCall({
        target: `${ctx.packageId}::reward_pool::withdraw`,
        arguments: [tx.object(poolId), tx.object(shareId)],
      });
      tx.transferObjects([coin], ctx.attackerAddress);
    },
    ctx.attackerAddress,
    "attacker withdraw",
  );
}

