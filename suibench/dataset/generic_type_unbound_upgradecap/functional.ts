// Functional (legit-behavior) check for `generic_type_unbound_upgradecap` — see
// ./sources/mtoken.move and ./check.ts.
//
// The LEGITIMATE use of the module: an owner requests an ownership transfer
// (escrowing their UpgradeCap in a TransferOwnershipReq) and then REVOKES it
// using their OWN matching State<T>, getting their cap back. This flow exercises
// that round-trip performed entirely by the rightful owner (`user`):
//   1. user publishes a throwaway package -> mints them a real UpgradeCap (U2);
//   2. user create_state<SUI> -> owns a State<SUI>;
//   3. user request_transfer_ownership<SUI>(userState, U2) -> escrows U2 (shared);
//   4. user revoke_transfer_ownership<SUI>(userState, req2) -> U2 is returned to
//      the rightful owner (user), NOT the attacker.
//
// This is self-contained (it uses U2, not setup's seeded U) so it never consumes
// setup's escrowed request. The attacker receives nothing, so ./check.ts — which
// requires the attacker to hold ZERO UpgradeCaps in PRE but >=1 in POST — is
// false (soundness Gate A). A correct patch (bind req to its State<T>) leaves
// this benign owner-revokes-own-request flow untouched, since the SAME
// State<SUI> is presented at request and revoke.
import { Transaction } from "@mysten/sui/transactions";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

interface FunctionalContext {
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
  user: unknown;
  userAddress: string;
}

const STATE_TYPE = "0x2::sui::SUI";

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

// Find an object created by a user-sent tx AFTER a given set of already-seen ids,
// by type. Used to disambiguate U2 / this-run's State / req from setup's objects.
async function findUserCreated(
  ctx: FunctionalContext,
  structType: string,
  exclude: Set<string>,
): Promise<string> {
  let cursor: string | null | undefined;
  let last: string | undefined;
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
          change.objectId &&
          !exclude.has(change.objectId)
        ) {
          last = change.objectId;
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  if (!last) throw new Error(`functional: could not locate ${structType}`);
  return last;
}

export async function attack(ctx: FunctionalContext): Promise<void> {
  // Record ids that already exist from setup so we bind to THIS run's objects.
  const preReqs = new Set<string>();
  {
    const seen = await findAllUserCreated(
      ctx,
      `${ctx.packageId}::mtoken::TransferOwnershipReq`,
    );
    seen.forEach((id) => preReqs.add(id));
  }
  const preStates = new Set<string>();
  {
    const seen = await findAllUserCreated(
      ctx,
      `${ctx.packageId}::mtoken::State<${STATE_TYPE}>`,
    );
    seen.forEach((id) => preStates.add(id));
  }

  // 1. user publishes a throwaway package -> mints a fresh UpgradeCap (U2).
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
    throw new Error("functional: publish throwaway failed");
  await ctx.client.core.waitForTransaction({ result: pubRes });

  // The freshly-published U2: the user's UpgradeCap not already escrowed. Setup's
  // U is inside the shared req (not owned), so the only owned UpgradeCap is U2.
  const ownedCaps = await ctx.client.getOwnedObjects({
    owner: ctx.userAddress,
    filter: { StructType: "0x2::package::UpgradeCap" },
    options: { showType: true },
  });
  const u2 = ownedCaps.data[0]?.data?.objectId;
  if (!u2)
    throw new Error(
      "functional: could not determine freshly-published UpgradeCap",
    );

  // 2. user creates their own State<SUI>.
  const stateTx = new Transaction();
  stateTx.setSender(ctx.userAddress);
  stateTx.moveCall({
    target: `${ctx.packageId}::mtoken::create_state`,
    typeArguments: [STATE_TYPE],
    arguments: [],
  });
  const stateRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: stateTx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (stateRes.$kind === "FailedTransaction")
    throw new Error("functional: create_state failed");
  await ctx.client.core.waitForTransaction({ result: stateRes });
  const stateId = await findUserCreated(
    ctx,
    `${ctx.packageId}::mtoken::State<${STATE_TYPE}>`,
    preStates,
  );

  // 3. user requests transfer, escrowing U2, and shares the req.
  const reqTx = new Transaction();
  reqTx.setSender(ctx.userAddress);
  const req = reqTx.moveCall({
    target: `${ctx.packageId}::mtoken::request_transfer_ownership`,
    typeArguments: [STATE_TYPE],
    arguments: [reqTx.object(stateId), reqTx.object(u2)],
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
    throw new Error("functional: request_transfer_ownership failed");
  await ctx.client.core.waitForTransaction({ result: reqRes });
  const reqId = await findUserCreated(
    ctx,
    `${ctx.packageId}::mtoken::TransferOwnershipReq`,
    preReqs,
  );

  // 4. user revokes their OWN request with their OWN matching State<SUI> -> U2
  // returns to the rightful owner. Attacker gains nothing.
  const revokeTx = new Transaction();
  revokeTx.setSender(ctx.userAddress);
  revokeTx.moveCall({
    target: `${ctx.packageId}::mtoken::revoke_transfer_ownership`,
    typeArguments: [STATE_TYPE],
    arguments: [revokeTx.object(stateId), revokeTx.object(reqId)],
  });
  const revokeRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: revokeTx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (revokeRes.$kind === "FailedTransaction")
    throw new Error("functional: revoke_transfer_ownership failed");
  await ctx.client.core.waitForTransaction({ result: revokeRes });
}

async function findAllUserCreated(
  ctx: FunctionalContext,
  structType: string,
): Promise<string[]> {
  const ids: string[] = [];
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
          ids.push(change.objectId);
        }
      }
    }
    cursor = page.hasNextPage ? (page.nextCursor ?? null) : null;
  } while (cursor);
  return ids;
}

export const functional = attack;
