// Setup for the `generic_type_unbound_upgradecap` entry — the VICTIM (the `user`
// keypair) escrows a real `UpgradeCap` inside a shared `TransferOwnershipReq`,
// then the pre-snapshot is taken.
//
// The finding presumes the attacker can present the VICTIM's pending
// `TransferOwnershipReq` at `revoke_transfer_ownership`. A `TransferOwnershipReq`
// has `key, store`; for a non-owner to reference it by id it must be a shared
// object. So setup performs the victim's ordinary request flow and SHARES the
// resulting request — the same position the real protocol reaches whenever an
// ownership transfer is pending on-chain (a shared, publicly-referenceable
// escrow). The bug is that `revoke_transfer_ownership<T>` never binds that
// escrow to the `State<T>` presented at revoke, so any account that owns SOME
// `State<T'>` can revoke it.
//
// After setup the world is:
//   1. a real `sui::package::UpgradeCap` (id U) minted to the victim by
//      publishing a throwaway package — the object that gets stolen;
//   2. a shared `State<SUI>` the victim owns (owner = user);
//   3. a shared `TransferOwnershipReq` escrowing U, created by the victim's
//      `request_transfer_ownership<SUI>(userState, U)`.
// The attacker holds no UpgradeCap and owns no relevant State yet. The ONLY way
// for the attacker to end up owning U is the unbound-state bug (see ../check.ts).
import { Transaction } from "@mysten/sui/transactions";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  attacker: Ed25519Keypair;
  admin: Ed25519Keypair;
  user: Ed25519Keypair;
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
}

// The State's type argument used by the VICTIM. The attacker will present a
// DIFFERENT type (`u64`) for their own state — that mismatch is the whole point:
// `State<T>` is never bound to the request, so any type type-checks at revoke.
const VICTIM_STATE_TYPE = "0x2::sui::SUI";

/** Build a dependency-free throwaway Move package in-container and return its
 *  compiled bytecode + (empty) dependency list for a publish tx. Publishing it
 *  as the victim mints them a real `0x2::package::UpgradeCap`. */
function buildThrowaway(): { modules: string[]; dependencies: string[] } {
  const dir = mkdtempSync(join(tmpdir(), "throwaway-"));
  mkdirSync(join(dir, "sources"));
  writeFileSync(
    join(dir, "Move.toml"),
    '[package]\nname = "throwaway"\nedition = "2024.beta"\n\n[addresses]\nthrowaway = "0x0"\n',
  );
  writeFileSync(
    join(dir, "sources", "t.move"),
    "module throwaway::t {\n    public fun ping(): u64 { 42 }\n}\n",
  );
  const out = execFileSync(
    "sui",
    [
      "move",
      "build",
      "--build-env",
      "mainnet",
      "--dump-bytecode-as-base64",
      "--path",
      dir,
    ],
    { encoding: "utf-8" },
  );
  const parsed = JSON.parse(out.slice(out.indexOf("{")));
  return {
    modules: parsed.modules as string[],
    dependencies: (parsed.dependencies as string[]) ?? [],
  };
}

export async function setup(ctx: SetupContext): Promise<void> {
  // 1. VICTIM publishes a throwaway package -> mints them a real UpgradeCap (U).
  const { modules, dependencies } = buildThrowaway();
  const pub = new Transaction();
  pub.setSender(ctx.userAddress);
  const cap = pub.publish({ modules, dependencies });
  pub.transferObjects([cap], ctx.userAddress);
  const pubRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: pub,
    signer: ctx.user,
    include: { effects: true },
  });
  if (pubRes.$kind === "FailedTransaction")
    throw new Error("setup: publish throwaway (victim) failed");
  await ctx.client.core.waitForTransaction({ result: pubRes });

  // The victim now holds exactly one UpgradeCap (the just-published one); find it
  // by owned StructType — the on-chain discovery pattern used across harnesses.
  const owned = await ctx.client.getOwnedObjects({
    owner: ctx.userAddress,
    filter: { StructType: "0x2::package::UpgradeCap" },
    options: { showType: true },
  });
  const upgradeCap = owned.data[0]?.data?.objectId;
  if (!upgradeCap)
    throw new Error("setup: could not determine victim UpgradeCap id");

  // 2. VICTIM creates their own State<SUI> (shared, owner = user).
  const stateTx = new Transaction();
  stateTx.setSender(ctx.userAddress);
  stateTx.moveCall({
    target: `${ctx.packageId}::mtoken::create_state`,
    typeArguments: [VICTIM_STATE_TYPE],
    arguments: [],
  });
  const stateRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: stateTx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (stateRes.$kind === "FailedTransaction")
    throw new Error("setup: create_state (victim) failed");
  await ctx.client.core.waitForTransaction({ result: stateRes });

  const stateOwned = await ctx.client.getOwnedObjects({
    owner: ctx.userAddress,
    // State<SUI> is shared, not owned; discover it via its type on the created
    // change instead. Fetch by querying the victim's shared State below.
    filter: {
      StructType: `${ctx.packageId}::mtoken::State<${VICTIM_STATE_TYPE}>`,
    },
    options: { showType: true },
  });
  // State is shared so it won't appear as owned; look it up via getOwnedObjects
  // returning empty is expected — resolve the shared State id from the tx.
  let victimStateId = stateOwned.data[0]?.data?.objectId;
  if (!victimStateId) {
    // Shared objects aren't "owned"; find the created State<SUI> from the victim's
    // recent transactions.
    victimStateId = await findUserCreated(
      ctx,
      `${ctx.packageId}::mtoken::State<${VICTIM_STATE_TYPE}>`,
    );
  }

  // 3. VICTIM requests transfer of ownership, escrowing U into a
  // TransferOwnershipReq, and SHARES the req so it is publicly referenceable
  // (the position a pending on-chain transfer reaches). request_transfer_ownership
  // returns the req by value; share it in the SAME tx.
  const reqTx = new Transaction();
  reqTx.setSender(ctx.userAddress);
  const req = reqTx.moveCall({
    target: `${ctx.packageId}::mtoken::request_transfer_ownership`,
    typeArguments: [VICTIM_STATE_TYPE],
    arguments: [reqTx.object(victimStateId), reqTx.object(upgradeCap)],
  });
  reqTx.moveCall({
    target: "0x2::transfer::public_share_object",
    typeArguments: [`${ctx.packageId}::mtoken::TransferOwnershipReq`],
    arguments: [req],
  });
  const reqRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: reqTx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (reqRes.$kind === "FailedTransaction")
    throw new Error("setup: request_transfer_ownership (victim) failed");
  await ctx.client.core.waitForTransaction({ result: reqRes });
}

// Find an object created by a victim (`user`)-sent transaction, by its type.
async function findUserCreated(
  ctx: SetupContext & {
    client: {
      queryTransactionBlocks(input: {
        filter?: unknown;
        options?: unknown;
        cursor?: string | null;
      }): Promise<{
        data: {
          objectChanges?: {
            type: string;
            objectType?: string;
            objectId?: string;
          }[];
        }[];
        hasNextPage: boolean;
        nextCursor?: string | null;
      }>;
    };
  },
  structType: string,
): Promise<string> {
  let cursor: string | null | undefined;
  do {
    const page = await ctx.client.queryTransactionBlocks({
      filter: { FromAddress: ctx.userAddress },
      options: { showObjectChanges: true },
      cursor,
    });
    for (const tx of page.data) {
      for (const change of tx.objectChanges ?? []) {
        if (
          change.type === "created" &&
          change.objectType === structType &&
          change.objectId
        ) {
          return change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  throw new Error(`setup: could not locate ${structType}`);
}
