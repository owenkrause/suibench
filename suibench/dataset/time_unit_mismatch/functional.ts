// Functional (legit-behavior) check for `time_unit_mismatch` — see ../sources/lock.move.
//
// A CORRECT patch fixes the unit bug so the gate compares against
// `start_ms + lock_duration_secs * 1000` (secs → ms). It must NOT break the
// legitimate flow: a `lock` followed by a `withdraw` AFTER the intended unlock
// has genuinely elapsed should still succeed. Waiting 50 minutes isn't feasible,
// so we lock with a TINY `lock_duration_secs` (1 second) and withdraw only once
// that second has really passed under the correct conversion — exercising the
// "withdraw works once genuinely unlocked" path.
//
// Concretely (owner-gated, so the attacker locks and withdraws their OWN funds):
//   1. lock ~1 SUI for lock_duration_secs = 1,
//   2. wait ~2.5s — comfortably past the intended 1-second (=1000ms) unlock,
//   3. withdraw → must succeed on a correctly-patched contract.
//
// On the VULNERABLE contract this also succeeds (the buggy gate lifts even
// sooner), which is fine: functional.ts only asserts legit behavior is intact,
// never that the bug is absent — the exploit re-run (exploits/timelock-unit-mismatch.ts)
// tests that.
//
// Exports `attack(ctx)` (the confirmer runner's contract) so the existing
// container plumbing runs it unchanged; `functional` is a readable alias.
import { Transaction } from "@mysten/sui/transactions";
import { SUI_CLOCK_OBJECT_ID, normalizeStructTag } from "@mysten/sui/utils";
import type { Signer } from "@mysten/sui/cryptography";
import type { SuiClientTypes } from "@mysten/sui/client";
import type { SuiGrpcClient } from "@mysten/sui/grpc";

type TxResult = SuiClientTypes.TransactionResult<{
  effects: true;
  objectTypes: true;
}>;

interface FunctionalContext {
  client: SuiGrpcClient;
  packageId: string;
  attacker: Signer;
  attackerAddress: string;
}

const LOCK_AMOUNT_MIST = 1_000_000_000n; // ~1 SUI
const LOCK_DURATION_SECS = 1n; // intended unlock ~1s out (= 1000ms once patched)

export async function functional(ctx: FunctionalContext): Promise<void> {
  // --- lock ~1 SUI for 1 second ---
  const lockTx = new Transaction();
  lockTx.setSender(ctx.attackerAddress);
  const [coin] = lockTx.splitCoins(lockTx.gas, [
    lockTx.pure.u64(LOCK_AMOUNT_MIST),
  ]);
  lockTx.moveCall({
    target: `${ctx.packageId}::lock::lock`,
    arguments: [
      coin,
      lockTx.pure.u64(LOCK_DURATION_SECS),
      lockTx.object(SUI_CLOCK_OBJECT_ID),
    ],
  });
  const lockRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: lockTx,
    signer: ctx.attacker,
    include: { effects: true, objectTypes: true },
  });
  if (lockRes.$kind === "FailedTransaction")
    throw new Error("functional: lock transaction failed");
  await ctx.client.core.waitForTransaction({ result: lockRes });

  const vaultId = findCreatedVault(lockRes, `${ctx.packageId}::lock::Vault`);
  if (!vaultId)
    throw new Error("functional: could not locate the created lock::Vault");

  // Wait until the intended 1-second lock has GENUINELY elapsed (correct
  // conversion = 1000ms). 2.5s gives ample margin against clock skew.
  await new Promise((r) => setTimeout(r, 2500));

  // --- withdraw the now-matured lock — must succeed under a correct patch ---
  const wdTx = new Transaction();
  wdTx.setSender(ctx.attackerAddress);
  const withdrawn = wdTx.moveCall({
    target: `${ctx.packageId}::lock::withdraw`,
    arguments: [wdTx.object(vaultId), wdTx.object(SUI_CLOCK_OBJECT_ID)],
  });
  wdTx.transferObjects([withdrawn], ctx.attackerAddress);
  const wdRes = await ctx.client.core.signAndExecuteTransaction({
    transaction: wdTx,
    signer: ctx.attacker,
    include: { effects: true },
  });
  if (wdRes.$kind === "FailedTransaction") {
    throw new Error(
      "functional: matured withdraw failed — a correct patch must still allow it",
    );
  }
  await ctx.client.core.waitForTransaction({ result: wdRes });
}

function findCreatedVault(
  res: TxResult,
  vaultType: string,
): string | undefined {
  const tx = res.Transaction;
  if (!tx) return undefined;
  const types = tx.objectTypes ?? {};
  const want = normalizeStructTag(vaultType);
  for (const change of tx.effects?.changedObjects ?? []) {
    const got = types[change.objectId];
    if (
      change.idOperation === "Created" &&
      typeof got === "string" &&
      got.includes("::") &&
      normalizeStructTag(got) === want
    ) {
      return change.objectId;
    }
  }
  return undefined;
}

