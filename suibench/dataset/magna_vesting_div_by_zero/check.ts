// Snapshot-pure availability predicate for the vesting division-by-zero DoS.
// The exploit "succeeds" (the harm occurred) iff the victim withdraw V did NOT
// complete successfully.
//
// The guard-the-denominator patch (assert-free — it returns 0 vested when a
// divisor is 0) makes the SAME victim withdraw SUCCEED under patch. Keep the
// non-success status guard, but also distinguish the two genuine division
// instructions from subtraction underflow and unrelated victim failures.
import type { Check, CheckResult } from "core";

const LABEL_ID = "vesting-div-by-zero" as const;

// The denial must be the labeled unguarded division-by-zero, not some other
// abort in the withdraw flow. Anchor on the runtime arithmetic fault raised
// inside `calc_vested_piece_amount` at one of its two division instructions;
// the guard-the-divisor patch makes V succeed (message null), and an unrelated
// abort names a different location. A missing or malformed outcome fails
// closed.
export const check: Check = (delta, params): CheckResult => {
  const v = delta.post.victim;
  if (v === undefined || v.status === "success") return { witnesses: [] };
  const msg = v.message ?? "";
  const location = / in '([^']+)' \(instruction (8|20)\)$/.exec(msg);
  const witnessed =
    /MovePrimitiveRuntimeError|MoveAbort/.test(msg) &&
    location !== null &&
    location[1] === `${params.packageId}::vesting::calc_vested_piece_amount`;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
