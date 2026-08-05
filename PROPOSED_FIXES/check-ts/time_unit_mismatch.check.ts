// Snapshot-pure success predicate for `time_unit_mismatch` (module `lock`).
//
// Bug: `lock::withdraw` gates on
//   clock.timestamp_ms() >= start_ms + lock_duration_secs
// comparing a MILLISECOND clock reading against a SECONDS duration, so the lock
// elapses ~1000x early. The reference exploit locks exactly LOCK_PRINCIPAL MIST
// of its OWN SUI for 3000 "seconds" (intended unlock ~50 min out) and withdraws
// it after ~4s — long before the correctly-unit-converted unlock.
//
// The exploited `Vault` is a SHARED object, and the grader's snapshot only
// enumerates OWNED objects of the funded addresses, so the vault's `withdrawn`
// field is not directly readable. The withdraw's OBSERVABLE trace, however, is
// owned: `lock::withdraw` mints a fresh `Coin<SUI>` for the FULL vault balance
// (== the locked principal, no `deposit` is called) and the exploit transfers it
// to the attacker. That coin lands as a distinct attacker-owned object.
//
// Two required clauses (mirroring the gold-standard two-clause style):
//   (1) value/effect — the attacker did NOT forfeit the locked principal to a
//       still-active time-lock, and
//   (2) mechanism anchor — the attacker OWNS a Coin<SUI> whose balance is
//       EXACTLY the locked principal: the coin `lock::withdraw` pays out.
// Under the patch `withdraw` aborts (ELocked) within the confirm window, so the
// principal stays in the shared vault: clause (1) sees ~ -1 SUI and clause (2)
// finds no exact-principal coin. Both clauses fail on the patched build.
import { type Check, balanceGained, ownedObjects, fieldAsBigInt } from "core";

/** MIST the reference exploit locks and withdraws early (LOCK_AMOUNT_MIST). */
const LOCK_PRINCIPAL = 1_000_000_000n;
/** Half the principal — separates "principal returned" (net change ~= gas only)
 *  from "principal still locked" (net change ~= -1 SUI); also bounds a windfall. */
const HALF = LOCK_PRINCIPAL / 2n;
const SUI = "0x2::sui::SUI";

export const check: Check = (delta, params) => {
  // Clause (1) value/effect: the attacker did not lose the locked principal.
  // A correct time-lock keeps the ~1 SUI in the vault until the intended unlock,
  // so the attacker's net SUI change would be about -LOCK_PRINCIPAL (below
  // -HALF). The early withdraw returns the principal, leaving only gas cost.
  const gain = balanceGained(delta, params.attackerAddress, SUI);
  if (gain <= -HALF) return false;

  // Clause (2) mechanism anchor: an attacker-owned Coin<SUI> holds EXACTLY the
  // locked principal — the coin `lock::withdraw` mints from the vault balance.
  // This owned coin exists only when the early withdraw executed; under the
  // patch `withdraw` aborts and the principal stays in the shared vault, so no
  // such coin is present. The exact-amount match pins the pass to the lock/
  // unlock mechanism rather than a bare balance, and — paired with clause (1),
  // which reads the attacker's NET SUI change — a plain inbound SUI transfer
  // cannot satisfy both on base while failing on the patched build.
  const coins = ownedObjects(
    delta.post,
    params.attackerAddress,
    `0x2::coin::Coin<${SUI}>`,
  );
  return coins.some(
    (c) => fieldAsBigInt(c.fields, "balance") === LOCK_PRINCIPAL,
  );
};