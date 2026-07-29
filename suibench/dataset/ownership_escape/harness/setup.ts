// Setup for the `ownership_escape` entry — the SELLER (admin) lists an item for
// sale, then the pre-snapshot is taken.
//
// As ADMIN we mint one `Item` (in its own tx so its object id is observable),
// then `list_item` it, which wraps it in a SHARED `Listing` recording
// `seller = admin`. After setup the world is:
// a shared `Listing` holding an `Item` that belongs to the admin (they listed
// it), and the attacker holds no such Item. The attacker never legitimately
// owns this Item — the only ways to acquire it are `buy_item` (paying the seller
// their price) or `cancel_listing` (which SHOULD be restricted to the seller).
// That listed-by-admin / attacker-holds-nothing starting position is what makes
// the check's "attacker took the seeded Item for free" predicate sound
// (see ./check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiJsonRpcClient } from "@mysten/sui/jsonRpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";

interface SetupContext {
  client: SuiJsonRpcClient & {
    getOwnedObjects(input: {
      owner: string;
      filter?: unknown;
      options?: unknown;
    }): Promise<{ data: { data?: { objectId?: string } }[] }>;
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

// The item's list price, in MIST. The benign buyer pays exactly this to the
// seller; the exploit pays nothing.
const LIST_PRICE = 1_000_000_000n; // 1 SUI

export async function setup(ctx: SetupContext): Promise<void> {
  // TWO transactions on purpose. If we minted-and-listed in a single PTB the
  // Item would be created-and-wrapped into the Listing atomically and its object
  // id would never surface as a top-level `created` change — leaving nothing for
  // check.ts to pin the theft to except the Item's field content, which a
  // permissionless `mint_item(b"rare-sword", 100)` decoy could forge. Minting in
  // its own tx makes the Item a top-level owned object of the admin, so its id
  // appears in that tx's objectChanges and check.ts can pin the EXACT seeded
  // object (see ./check.ts::findSeededItemId).

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
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.adminAddress,
    filter: { StructType: `${ctx.packageId}::marketplace::Item` },
    options: { showType: true },
  });
  const seededItemId = owned.data[0]?.data?.objectId;
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
