// Setup for whitelist_campaign_unbound.
//
// Two independent gated sales, each a shared Campaign with its own shared
// Whitelist (the Whitelist records both its campaign_id and its creating admin):
//
//   Campaign A  — the GATED sale, created by ADMIN. Whitelist_A lists the USER
//                 (a legitimate member) but NOT the attacker.
//   Campaign B  — the attacker's OWN sale, created by the ATTACKER. Whitelist_B
//                 lists the ATTACKER (so the attacker is legitimately whitelisted
//                 *somewhere* — on B, never on A).
//
// The attacker is funded (by the localnet genesis gas the container gives every
// role) so they can pay real SUI into `invest`. `create_campaign` records
// `admin = ctx.sender()`, so campaign A is the one whose `admin == adminAddress`
// and campaign B the one whose `admin == attackerAddress` — that is how check.ts
// tells the two apart. Each whitelist records `campaign_id` and `admin`, so
// whitelist A is the admin-owned list whose `campaign_id == id(campaignA)`.
import { Transaction } from "@mysten/sui/transactions";
import type { SuiGrpcClient } from "@mysten/sui/grpc";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
interface NativeChain {
  findCreatedObjects(sender: string): Promise<
    readonly { id: string; type: string; digest: string; checkpoint: bigint }[]
  >;
}

interface SetupContext {
  client: SuiGrpcClient;
  chain: NativeChain;
  packageId: string;
  attacker: Ed25519Keypair;
  admin: Ed25519Keypair;
  user: Ed25519Keypair;
  attackerAddress: string;
  adminAddress: string;
  userAddress: string;
}

const CAMPAIGN_T = (pkg: string) => `${pkg}::launchpad::Campaign`;
const WHITELIST_T = (pkg: string) => `${pkg}::launchpad::Whitelist`;

// Run a tx and wait for it (no created-object read).
async function send(
  ctx: SetupContext,
  tx: Transaction,
  signer: Ed25519Keypair,
  signerAddr: string,
  label: string,
): Promise<void> {
  tx.setSender(signerAddr);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`setup: ${label} tx failed`);
  await ctx.client.core.waitForTransaction({ result: res });
}

// Run a tx, wait for it, and return the object ids it CREATED of `wantType`.
async function runAndCreated(
  ctx: SetupContext,
  tx: Transaction,
  signer: Ed25519Keypair,
  signerAddr: string,
  wantType: string,
  label: string,
): Promise<string[]> {
  tx.setSender(signerAddr);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(`setup: ${label} tx failed`);
  await ctx.client.core.waitForTransaction({ result: res });
  const digest = res.Transaction?.digest;

  const ids = (await ctx.chain.findCreatedObjects(signerAddr))
    .filter(
      (object) =>
        object.type === wantType && (!digest || object.digest === digest),
    )
    .map((object) => object.id);
  if (ids.length > 0) return ids;
  throw new Error(`setup: ${label} created no ${wantType}`);
}

export async function setup(ctx: SetupContext): Promise<void> {
  const pkg = ctx.packageId;

  // --- Campaign A (gated sale), created by ADMIN ---
  const txA = new Transaction();
  txA.moveCall({ target: `${pkg}::launchpad::create_campaign` });
  const [campaignA] = await runAndCreated(
    ctx,
    txA,
    ctx.admin,
    ctx.adminAddress,
    CAMPAIGN_T(pkg),
    "create campaign A",
  );

  // Whitelist_A for campaign A, add the USER (legit member) — NOT the attacker.
  const txWA = new Transaction();
  txWA.moveCall({
    target: `${pkg}::launchpad::create_whitelist`,
    arguments: [txWA.object(campaignA)],
  });
  const [whitelistA] = await runAndCreated(
    ctx,
    txWA,
    ctx.admin,
    ctx.adminAddress,
    WHITELIST_T(pkg),
    "create whitelist A",
  );

  const txAddU = new Transaction();
  txAddU.moveCall({
    target: `${pkg}::launchpad::add_member`,
    arguments: [
      txAddU.object(whitelistA),
      txAddU.pure.address(ctx.userAddress),
    ],
  });
  await send(
    ctx,
    txAddU,
    ctx.admin,
    ctx.adminAddress,
    "add user to whitelist A",
  );

  // --- Campaign B (attacker's own sale), created by the ATTACKER ---
  const txB = new Transaction();
  txB.moveCall({ target: `${pkg}::launchpad::create_campaign` });
  const [campaignB] = await runAndCreated(
    ctx,
    txB,
    ctx.attacker,
    ctx.attackerAddress,
    CAMPAIGN_T(pkg),
    "create campaign B",
  );

  // Whitelist_B for campaign B, add the ATTACKER (legit member on B).
  const txWB = new Transaction();
  txWB.moveCall({
    target: `${pkg}::launchpad::create_whitelist`,
    arguments: [txWB.object(campaignB)],
  });
  const [whitelistB] = await runAndCreated(
    ctx,
    txWB,
    ctx.attacker,
    ctx.attackerAddress,
    WHITELIST_T(pkg),
    "create whitelist B",
  );

  const txAddA = new Transaction();
  txAddA.moveCall({
    target: `${pkg}::launchpad::add_member`,
    arguments: [
      txAddA.object(whitelistB),
      txAddA.pure.address(ctx.attackerAddress),
    ],
  });
  await send(
    ctx,
    txAddA,
    ctx.attacker,
    ctx.attackerAddress,
    "add attacker to whitelist B",
  );
}
