// Setup for the `generic_type_unbound_upgradecap` entry — the VICTIM (the `user`
// keypair) escrows the PROTOCOL's own `UpgradeCap` inside a shared
// `TransferOwnershipReq`, then the pre-snapshot is taken.
//
// The escrowed cap is the challenge package's OWN `UpgradeCap` (minted to the
// deployer/`admin` when the harness publishes the package, `fields.package ===
// packageId`) — exactly the real Matrixdock scenario, where the protocol escrows
// its own upgrade authority while an ownership transfer is pending. Anchoring the
// oracle on THIS cap (../check.ts) is what makes it mechanism-specific: a decoy
// self-mint (publish any package) yields a cap for a DIFFERENT package and does
// not satisfy the check.
//
// The finding presumes the attacker can present the VICTIM's pending
// `TransferOwnershipReq` at `revoke_transfer_ownership`. A `TransferOwnershipReq`
// has `key, store`; for a non-owner to reference it by id it must be a shared
// object. So setup performs the victim's ordinary request flow and SHARES the
// resulting request — the same position the real protocol reaches whenever an
// ownership transfer is pending on-chain (a shared, publicly-referenceable
// escrow). The bug is that `revoke_transfer_ownership<T>` never binds that escrow
// to the `State<T>` presented at revoke, so any account owning SOME `State<T'>`
// can revoke it.
//
// After setup the world is:
//   1. the challenge package's `UpgradeCap` (id U, `package === packageId`),
//      handed by the deployer to the victim and then escrowed — the stolen object;
//   2. a shared `State<SUI>` the victim owns (owner = user);
//   3. a shared `TransferOwnershipReq` escrowing U, created by the victim's
//      `request_transfer_ownership<SUI>(userState, U)`.
// The attacker holds no UpgradeCap and owns no relevant State yet. The ONLY way
// for the attacker to end up owning a cap governing the challenge package is the
// unbound-state bug (see ../check.ts).
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { normalizeStructTag } from "@mysten/sui/utils";

interface SetupContext {
  client: SuiGrpcClient;
  chain: {
    findCreatedObjects(
      sender: string,
    ): Promise<
      readonly {
        id: string;
        type: string;
        digest: string;
        checkpoint: bigint;
      }[]
    >;
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

// Canonicalize a 0x-prefixed id for comparison (RPC may strip leading zeros).
const norm = (id: string): string =>
  "0x" + id.replace(/^0x/, "").replace(/^0+/, "");

export async function setup(ctx: SetupContext): Promise<void> {
  // 1. Locate the challenge package's own UpgradeCap (minted to admin by the
  //    harness publish; `fields.package === packageId`) and hand it to the victim.
  const { objects: adminCaps } = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: "0x2::package::UpgradeCap",
    include: { json: true },
  });
  const wantPkg = norm(ctx.packageId);
  const protocolCap = adminCaps.find(
    (object) =>
      norm(
        String((object.json as { package?: unknown } | null)?.package ?? ""),
      ) === wantPkg,
  )?.objectId;
  if (!protocolCap)
    throw new Error("setup: could not find the challenge package's UpgradeCap");

  const giveTx = new Transaction();
  giveTx.setSender(ctx.adminAddress);
  giveTx.transferObjects([giveTx.object(protocolCap)], ctx.userAddress);
  const giveRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: giveTx,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (giveRes.$kind === "FailedTransaction")
    throw new Error("setup: hand UpgradeCap to victim failed");
  await ctx.client.core.waitForTransaction({ result: giveRes });

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

  // State<SUI> is shared so it won't appear as owned; resolve it from the
  // victim's created object changes.
  const victimStateId = await findUserCreated(
    ctx,
    `${ctx.packageId}::mtoken::State<${VICTIM_STATE_TYPE}>`,
  );

  // 3. VICTIM requests transfer of ownership, escrowing U into a
  // TransferOwnershipReq, and SHARES the req so it is publicly referenceable
  // (the position a pending on-chain transfer reaches).
  const reqTx = new Transaction();
  reqTx.setSender(ctx.userAddress);
  const req = reqTx.moveCall({
    target: `${ctx.packageId}::mtoken::request_transfer_ownership`,
    typeArguments: [VICTIM_STATE_TYPE],
    arguments: [reqTx.object(victimStateId), reqTx.object(protocolCap)],
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
  ctx: SetupContext,
  structType: string,
): Promise<string> {
  const wanted = normalizeStructTag(structType);
  const object = (await ctx.chain.findCreatedObjects(ctx.userAddress)).find(
    (created) => created.type === wanted,
  );
  if (object) return object.id;
  throw new Error(`setup: could not locate ${structType}`);
}
