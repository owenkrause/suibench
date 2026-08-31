// Functional (legit-behavior) check for `navi_supply_balance_public`.
//
// The legitimate path the patch must preserve is deposit -> withdraw: a user backs
// its recorded supply balance with a real deposit, then withdraws against it. This
// exercises exactly that as the ADMIN (the only party holding TOKEN after setup):
// the admin locates the shared Storage, `deposit`s 500 TOKEN (crediting its supply
// record by 500), then `withdraw`s 500 back out. Net TOKEN for the admin is 0, and
// this is the path a correct patch — which only makes `increase_supply_balance`
// internal — keeps fully working.
//
// It must NOT trip ./check.ts, which scores the ATTACKER's TOKEN gain. Here the
// only actor is the admin, so the attacker gains nothing and the predicate is
// false. If check.ts scored this benign deposit/withdraw as a success, the
// predicate would be unsound (soundness Gate A).
//
// Exports `attack(ctx)` (aliased `functional`) with the confirmer's AttackContext
// shape — the runner only ever calls `attack`. Signs with the ADMIN keypair.
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
  admin: unknown;
  adminAddress: string;
  attackerAddress: string;
}

async function findStorage(ctx: FunctionalContext): Promise<string> {
  const storageType = `${ctx.packageId}::storage::Storage`;
  const storage = (await ctx.chain.findCreatedObjects(ctx.adminAddress)).find(
    (object) => object.type === storageType,
  );
  if (storage) return storage.id;
  throw new Error("functional: could not locate the shared Storage");
}

// The admin still holds the remainder of the 1_000_000 TOKEN mint after setup.
async function findAdminToken(ctx: FunctionalContext): Promise<string> {
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `0x2::coin::Coin<${ctx.packageId}::token::TOKEN>`,
    include: { json: true },
  });
  const id = objects[0]?.objectId;
  if (!id) throw new Error("functional: admin holds no TOKEN coin");
  return id;
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const storageId = await findStorage(ctx);
  const tokenId = await findAdminToken(ctx);

  const tx = new Transaction();
  tx.setSender(ctx.adminAddress);

  // Legit deposit: back a 500 supply balance with a real 500-TOKEN deposit.
  const [depositCoin] = tx.splitCoins(tx.object(tokenId), [tx.pure.u64(500)]);
  tx.moveCall({
    target: `${ctx.packageId}::storage::deposit`,
    arguments: [tx.object(storageId), depositCoin],
  });
  // Legit withdraw: pull the same 500 back out against the recorded supply.
  const withdrawn = tx.moveCall({
    target: `${ctx.packageId}::storage::withdraw`,
    arguments: [tx.object(storageId), tx.pure.u64(500)],
  });
  tx.transferObjects([withdrawn], ctx.adminAddress);

  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: deposit/withdraw failed");
  await ctx.client.core.waitForTransaction({ result: res });
}

