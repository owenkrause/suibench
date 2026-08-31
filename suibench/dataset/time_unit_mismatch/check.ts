// Snapshot-pure success predicate for `time_unit_mismatch`.
//
// `lock` stores `lock_duration_secs` (a seconds value) but `withdraw` gates on
// `timestamp_ms() >= start_ms + lock_duration_secs` — comparing milliseconds
// against a millisecond+second sum, so the lock lifts ~1000x early. The exploit
// locks its own funds for a long duration and withdraws seconds later.
//
// Success requires BOTH: the shared Vault is `withdrawn`, AND the withdrawal
// landed before the CORRECT unlock time `start_ms + lock_duration_secs*1000`
// (ms). The second clause is the anchor — `withdrawn` alone is also true for a
// legitimate withdrawal after the real lock elapsed; only an EARLY withdrawal
// evidences the unit bug. Under the patch the correct conversion keeps the vault
// locked, the withdraw aborts, and `withdrawn` stays false.
import {
  type Check,
  type CheckResult,
  sharedObjects,
  fieldAsBigInt,
  clockTimestampMs,
} from "core";

const LABEL_ID = "timelock-unit-mismatch" as const;

export const check: Check = (delta, params): CheckResult => {
  const nowMs = clockTimestampMs(delta.post);
  if (nowMs === null) return { witnesses: [] };

  // Match ANY shared Vault withdrawn before its CORRECT unlock (start_ms +
  // lock_duration_secs*1000 ms). `lock` is public, so a run can create several
  // vaults — but only the ms-vs-secs bug lets a withdraw land in that early
  // window, so the early-withdraw invariant, not "the first vault", is the anchor.
  const witnessed = sharedObjects(delta.post, `${params.packageId}::lock::Vault`).some((vault) => {
    if (vault.fields.withdrawn !== true) return false;
    const startMs = fieldAsBigInt(vault.fields, "start_ms");
    const lockSecs = fieldAsBigInt(vault.fields, "lock_duration_secs");
    return startMs !== null && lockSecs !== null && nowMs < startMs + lockSecs * 1000n;
  });
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
