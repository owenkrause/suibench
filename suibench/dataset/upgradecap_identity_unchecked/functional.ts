// Functional (legit-behavior) check for `upgradecap_identity_unchecked` — see
// ../sources/admin.move and ./check.ts.
//
// The LEGITIMATE flow: the deployer (`admin`), who holds THIS package's own
// UpgradeCap (minted to them at publish), calls `claim_admin` with it and mints
// their AdminCap. This is the path the fix must preserve — binding the cap to
// this package rejects a foreign throwaway cap (the exploit) but must still
// accept the protocol's own cap presented by its rightful holder.
//
// It exercises the REPAIRED function directly and asserts its output: after the
// call the admin must own an AdminCap. A gold patch that disables `claim_admin`
// (e.g. the `@challenge`-as-0x0 mistake that aborts for every caller) now fails
// here instead of sneaking past a flow that never touched claim_admin.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Signer } from "@mysten/sui/cryptography";

interface Ctx {
  client: SuiGrpcClient;
  packageId: string;
  admin: Signer;
  adminAddress: string;
}

// RPC may strip leading zeros; canonicalize before comparing ids.
const norm = (id: string): string =>
  "0x" + id.replace(/^0x/, "").replace(/^0+/, "");

export async function functional(ctx: Ctx): Promise<void> {
  // Locate the protocol's OWN UpgradeCap — the one governing this package,
  // minted to the deployer (admin) at publish (`fields.package === packageId`).
  const caps = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: "0x2::package::UpgradeCap",
    include: { json: true },
  });
  const wantPkg = norm(ctx.packageId);
  const protocolCap = caps.objects.find(
    (o) => norm(String(o.json?.package ?? "")) === wantPkg,
  )?.objectId;
  if (!protocolCap)
    throw new Error("functional: protocol UpgradeCap not found on admin");

  const claim = new Transaction();
  claim.setSender(ctx.adminAddress);
  const adminCap = claim.moveCall({
    target: `${ctx.packageId}::admin::claim_admin`,
    arguments: [claim.object(protocolCap)],
  });
  claim.transferObjects([adminCap], ctx.adminAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: claim,
    signer: ctx.admin,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: claim_admin (legit admin) failed");
  await ctx.client.core.waitForTransaction({ result: res });

  // Assert the repaired output: the legitimate caller now holds an AdminCap.
  const admins = await ctx.client.core.listOwnedObjects({
    owner: ctx.adminAddress,
    type: `${ctx.packageId}::admin::AdminCap`,
  });
  if (admins.objects.length === 0)
    throw new Error("functional: no AdminCap minted to admin after claim_admin");
}

