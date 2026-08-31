// Functional (legit-behavior) check for `whitelist_campaign_unbound` — see
// ../sources/launchpad.move.
//
// Each one-mechanism patch must preserve a correctly matched investment by a
// legitimate member. The USER, whom setup.ts added to Whitelist_A, invests in
// campaign A with Whitelist_A; this remains valid under all three overlays.
//
// This is exported as `attack(ctx)` because the confirmer runner only ever calls
// `attack`; here it performs a benign, correctly-bound invest.
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
  user: Signer;
  userAddress: string;
  adminAddress: string;
}

async function createdByOfType(
  ctx: FunctionalContext,
  creator: string,
  wantType: string,
): Promise<string[]> {
  return (await ctx.chain.findCreatedObjects(creator))
    .filter((object) => object.type === wantType)
    .map((object) => object.id);
}

export async function functional(ctx: FunctionalContext): Promise<void> {
  const pkg = ctx.packageId;
  const CAMPAIGN = `${pkg}::launchpad::Campaign`;
  const WHITELIST = `${pkg}::launchpad::Whitelist`;

  // Campaign A and Whitelist_A are the admin-created gated sale + its own list.
  const campaignA = (await createdByOfType(ctx, ctx.adminAddress, CAMPAIGN))[0];
  if (!campaignA) throw new Error("functional: no admin campaign (A) found");
  const adminWhitelists = await createdByOfType(
    ctx,
    ctx.adminAddress,
    WHITELIST,
  );

  // Pick the admin whitelist that belongs to campaign A (its campaign_id matches).
  let whitelistA: string | undefined;
  for (const w of adminWhitelists) {
    const { object } = await ctx.client.core.getObject({
      objectId: w,
      include: { json: true },
    });
    if (object.json?.campaign_id === campaignA) {
      whitelistA = w;
      break;
    }
  }
  if (!whitelistA)
    throw new Error("functional: no whitelist A for campaign A found");

  // The USER (a legit member of Whitelist_A) invests in campaign A with the
  // CORRECT whitelist — the legitimate path a valid patch must preserve.
  const tx = new Transaction();
  tx.setSender(ctx.userAddress);
  const [payment] = tx.splitCoins(tx.gas, [tx.pure.u64(1_000_000n)]);
  tx.moveCall({
    target: `${pkg}::launchpad::invest`,
    arguments: [tx.object(campaignA), tx.object(whitelistA), payment],
  });
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: tx,
    signer: ctx.user,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error(
      "functional: matched invest (user→campaign A w/ whitelist A) failed",
    );
  await ctx.client.core.waitForTransaction({ result: res });
}
