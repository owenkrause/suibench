// Setup for the `ownership_escape` entry — the SELLER (admin) lists an item for
// sale, then the pre-snapshot is taken.
//
// As ADMIN we mint one `Item`, then `list_item` wraps it in a SHARED `Listing`
// recording the exact `item_id` and `seller = admin`. The check uses that
// pre-state Listing as its identity anchor: a successful exact-package
// `Cancellation` emitted for the same item and seller witnesses the bug only
// when its actor is the attacker and differs from the seller. Final balances
// and final Item ownership are intentionally irrelevant.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiGrpcClient & {
    core: {
      signAndExecuteTransaction: (input: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string; FailedTransaction?: unknown }>;
      waitForTransaction: (input: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  admin: Ed25519Keypair;
  attacker: Ed25519Keypair;
  attackerAddress: string;
  adminAddress: string;
}

// The item's list price, in MIST, used by the benign functional buyer. The
// cancellation witness does not infer authorization from seller balance changes.
const LIST_PRICE = 1_000_000_000n; // 1 SUI

export async function setup(ctx: SetupContext): Promise<void> {
  // TWO transactions on purpose: setup first discovers the minted Item's object
  // id by type, then supplies that id to the listing transaction. Once listing
  // commits, its pre-state `item_id` and `seller` fields are the authoritative
  // identity that check.ts binds to the attack-phase `Cancellation` event.

  // tx1: mint the Item alone → it is returned to the admin as a top-level owned
  // object, so its object id is a `created` change on this admin-sent tx.
  const mintTx = new Transaction();
  mintTx.setSender(ctx.adminAddress);
  const item = mintTx.moveCall({
    target: `${ctx.packageId}::marketplace::mint_item`,
    arguments: [
      mintTx.pure.vector("u8", Array.from(Buffer.from("rare-sword"))),
      mintTx.pure.u64(100),
    ],
  });
  mintTx.transferObjects([item], ctx.adminAddress);
  const mintRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: mintTx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (mintRes.$kind === "FailedTransaction")
    throw new Error("setup: mint_item transaction failed");
  await ctx.client.core.waitForTransaction({ result: mintRes });

  // The admin now holds exactly one Item (the just-minted one); find its id by
  // its owned StructType — the same on-chain discovery every other harness uses,
  // rather than parsing the SDK's tx-result shape.
  const { objects } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `${ctx.packageId}::marketplace::Item`,
    include: { json: true },
  });
  const seededItemId = objects[0]?.objectId;
  if (!seededItemId)
    throw new Error("setup: could not determine minted Item id");

  // tx2: list the just-minted Item as the admin (seller). `list_item` shares the
  // resulting Listing so any buyer can reference it.
  const listTx = new Transaction();
  listTx.setSender(ctx.adminAddress);
  listTx.moveCall({
    target: `${ctx.packageId}::marketplace::list_item`,
    arguments: [listTx.object(seededItemId), listTx.pure.u64(LIST_PRICE)],
  });
  const listRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: listTx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (listRes.$kind === "FailedTransaction")
    throw new Error("setup: list_item transaction failed");
  await ctx.client.core.waitForTransaction({ result: listRes });
}
