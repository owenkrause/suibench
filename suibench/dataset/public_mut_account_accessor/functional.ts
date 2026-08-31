// Functional (legit-behavior) check for `public_mut_account_accessor`.
//
// The rightful owner withdrawing their OWN collateral: the VICTIM (user) publishes
// the same style of helper module and calls it against their OWN address, pulling
// their own funds back out. This is benign — the attacker gains nothing — so it
// must score `confirmed = false` (Gate A). It also works under the correct patch
// (withdraw's `owner == sender` check passes for the account's own owner),
// asserting that binding withdraw to ownership does not break legitimate use.
import { Transaction } from "@mysten/sui/transactions";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const WITHDRAW_AMOUNT = 1_000n; // the user's own seeded collateral

interface TxResult {
  $kind?: string;
  FailedTransaction?: unknown;
}

interface CreatedObject {
  readonly id: string;
  readonly type: string;
}

interface PublishedPackage {
  readonly id: string;
}

interface Ctx {
  client: {
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<TxResult>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  chain: {
    findCreatedObjects(sender: string): Promise<readonly CreatedObject[]>;
    findPublishedPackages(sender: string): Promise<readonly PublishedPackage[]>;
  };
  packageId: string;
  user: unknown;
  userAddress: string;
  adminAddress: string;
}

async function findMarketMaker(ctx: Ctx): Promise<string> {
  const mmType = `${ctx.packageId}::market_maker::MarketMaker`;
  const marketMaker = (
    await ctx.chain.findCreatedObjects(ctx.adminAddress)
  ).find((object) => object.type === mmType);
  if (marketMaker) return marketMaker.id;
  throw new Error("functional: MarketMaker not found");
}

async function findPublishedPkg(ctx: Ctx, sender: string): Promise<string> {
  const packages = await ctx.chain.findPublishedPackages(sender);
  const latest = packages[packages.length - 1];
  if (latest) return latest.id;
  throw new Error("functional: no published package found");
}

function buildHelperPkg(packageId: string): {
  modules: string[];
  dependencies: string[];
} {
  const targetToml = "/workspace/target/Move.toml";
  let toml = readFileSync(targetToml, "utf-8");
  if (!toml.includes("published-at")) {
    toml = toml.replace(
      "[package]",
      `[package]\npublished-at = "${packageId}"`,
    );
    toml = toml.replace('challenge = "0x0"', `challenge = "${packageId}"`);
    writeFileSync(targetToml, toml);
  }
  const dir = mkdtempSync(join(tmpdir(), "helper-"));
  mkdirSync(join(dir, "sources"));
  writeFileSync(
    join(dir, "Move.toml"),
    `[package]\nname = "att"\nedition = "2024.beta"\n\n[dependencies]\nchallenge = { local = "/workspace/target" }\n\n[addresses]\natt = "0x0"\nchallenge = "${packageId}"\n`,
  );
  writeFileSync(
    join(dir, "sources", "drain.move"),
    `module att::drain {\n` +
      `    use sui::coin::Coin;\n` +
      `    public fun go(mm: &mut challenge::market_maker::MarketMaker, who: address, amount: u64, ctx: &mut TxContext): Coin<challenge::asset::ASSET> {\n` +
      `        let acct = challenge::market_maker::account_mut(mm, who);\n` +
      `        challenge::market_maker::withdraw(acct, amount, ctx)\n` +
      `    }\n` +
      `}\n`,
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

export async function functional(ctx: Ctx): Promise<void> {
  const mm = await findMarketMaker(ctx);

  const { modules, dependencies } = buildHelperPkg(ctx.packageId);
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
    throw new Error("functional: publish helper failed");
  await ctx.client.core.waitForTransaction({ result: pubRes });
  const pkgId = await findPublishedPkg(ctx, ctx.userAddress);

  // The user withdraws their OWN collateral (who == userAddress).
  const call = new Transaction();
  call.setSender(ctx.userAddress);
  const withdrawn = call.moveCall({
    target: `${pkgId}::drain::go`,
    arguments: [
      call.object(mm),
      call.pure.address(ctx.userAddress),
      call.pure.u64(WITHDRAW_AMOUNT),
    ],
  });
  call.transferObjects([withdrawn], ctx.userAddress);
  const callRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: call,
    signer: ctx.user,
    include: { effects: true },
  });
  if (callRes.$kind === "FailedTransaction")
    throw new Error("functional: self-withdraw failed");
  await ctx.client.core.waitForTransaction({ result: callRes });
}
