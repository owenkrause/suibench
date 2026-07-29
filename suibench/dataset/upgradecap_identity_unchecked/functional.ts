// Functional (legit-behavior) check for `upgradecap_identity_unchecked` — see
// ../sources/admin.move and ./check.ts.
//
// A benign, non-exploit flow: the attacker publishes their OWN throwaway package
// (a perfectly legitimate thing to do — you get an UpgradeCap for your own
// package) but does NOT call `claim_admin`. Merely HOLDING an UpgradeCap is not
// the attack; the vulnerability is passing it to `claim_admin` to mint an
// AdminCap. So this flow leaves the attacker with no AdminCap and must score
// `confirmed = false` (Gate A). It runs identically on the vulnerable and patched
// contract (it never touches claim_admin), asserting that ordinary publishing is
// unaffected.
import { Transaction } from "@mysten/sui/transactions";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

interface Ctx {
  client: {
    core: {
      signAndExecuteTransaction: (i: {
        transaction: Transaction;
        signer: unknown;
        include?: unknown;
      }) => Promise<{ $kind?: string }>;
      waitForTransaction: (i: { result: unknown }) => Promise<unknown>;
    };
  };
  packageId: string;
  attacker: unknown;
  attackerAddress: string;
}

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

export async function attack(ctx: Ctx): Promise<void> {
  const { modules, dependencies } = buildThrowaway();
  const pub = new Transaction();
  pub.setSender(ctx.attackerAddress);
  const cap = pub.publish({ modules, dependencies });
  pub.transferObjects([cap], ctx.attackerAddress);
  const res = await ctx.client.core.signAndExecuteTransaction({
    transaction: pub,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (res.$kind === "FailedTransaction")
    throw new Error("functional: publish throwaway failed");
  await ctx.client.core.waitForTransaction({ result: res });
  // Deliberately do NOT call claim_admin — holding an UpgradeCap is not the attack.
}

export const functional = attack;
