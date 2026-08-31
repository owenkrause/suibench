// Two benign flows that must succeed (not abort) under every patched build
// variant: a fully-repaid collateral loan, and a partial cToken redemption.
// Exercises the same `record_default`/`redeem`/`borrow_collateralized`/
// `withdraw_collateral` API the reference exploits use — including the
// DefaultCap-gated `record_default` call in `harness/setup.ts` — so a patch
// can't break the ABI while still defeating its labeled mechanism.
//
// The redemption's `actual_payout == fair_written_off_payout` ONLY under the
// A patch (total_debt already written down to 0). Under base/B-patch this
// same smaller redemption still overpays — sawA's inequality holds too, just
// at 300-cToken scale instead of the full 500-cToken exploit. That's not a
// false positive: this flow is graded on compile+non-abort only (see
// scripts/verify-gold-patches.ts), its own events are never run through
// check.ts — only the separate exploit script's are, via confirmExploit.
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's
// AttackContext shape — the runner only ever calls `attack`.
import { Transaction } from "@mysten/sui/transactions";

interface CreatedObject {
  readonly id: string;
  readonly type: string;
  readonly digest: string;
  readonly checkpoint: bigint;
}

interface Ctx {
  client: {
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<unknown>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
      listOwnedObjects(i: {
        owner: string;
        type?: string;
        include?: { json?: boolean };
      }): Promise<{
        objects: { objectId: string; type: string; json?: unknown }[];
      }>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
  adminAddress: string;
}

async function findPool(ctx: Ctx): Promise<string> {
  const prefix = `${ctx.packageId}::lending_pool::Pool`;
  const pool = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === prefix,
  );
  if (pool) return pool.id;
  throw new Error("functional: Pool not found");
}
async function findReceipt(ctx: Ctx): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `${ctx.packageId}::lending_pool::CTokenReceipt`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no CTokenReceipt");
  return id;
}
async function findAssetCoin(ctx: Ctx): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.attackerAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::asset::ASSET>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("functional: attacker holds no ASSET");
  return id;
}

// Two benign flows, both of which every gold patch must preserve (i.e. must
// not abort — see the file header for why the redemption's fairness does NOT
// hold under base/B-patch and why that's still not a grading false positive):
//   1. a fully-repaid collateral loan (borrow -> repay -> withdraw_collateral):
//      CollateralRelease reports `debt_remaining == 0` under every variant.
//   2. a partial redemption (300 cTokens): Redemption is fair
//      (`actual_payout == fair_written_off_payout`) only under the A patch.
export async function functional(ctx: Ctx): Promise<void> {
  const pool = await findPool(ctx);
  const receipt = await findReceipt(ctx);
  const coll = await findAssetCoin(ctx);
  const tx = new Transaction();
  tx.setSender(ctx.attackerAddress);

  // Legit borrow: post 700, borrow 500, repay it in full, reclaim collateral.
  const [borrowed, debt] = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::borrow_collateralized`,
    arguments: [tx.object(pool), tx.object(coll), tx.pure.u64(500)],
  });
  tx.moveCall({
    target: `${ctx.packageId}::lending_pool::repay`,
    arguments: [tx.object(pool), debt, borrowed],
  });
  const back = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::withdraw_collateral`,
    arguments: [tx.object(pool), debt],
  });

  const [payout, leftover] = tx.moveCall({
    target: `${ctx.packageId}::lending_pool::redeem`,
    arguments: [tx.object(pool), tx.object(receipt), tx.pure.u64(300)],
  });
  tx.transferObjects([back, payout, leftover, debt], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  await ctx.client.core.waitForTransaction({ result: res });
}

