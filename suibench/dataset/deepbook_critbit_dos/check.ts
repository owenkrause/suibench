// Snapshot-pure availability predicate for the permanent-brick critbit DoS. The
// exploit "succeeds" iff the victim traversal V did NOT complete — the confirmer
// folds V's outcome into `delta.post.victim`.
//
// `!== "success"` (NOT gas_exhausted, unlike a loop-DoS): the bug is an out-of-
// bounds ASSERT, so the vulnerable victim op MoveAborts => non-success. The patch
// DELETES that assert, so on the SAME bricked state the victim op SUCCEEDS —
// "not success" cleanly separates bug from patch, and the benign tree succeeds.
import type { Check, CheckResult } from "core";

const LABEL_ID = "critbit-brick" as const;

// The denial must be the labeled out-of-bounds assert in `is_left_child`, not
// any other abort a "cancel every order" attempt might raise. Anchor on that
// MoveAbort location; the patch that deletes the assert makes V succeed (message
// null). A missing outcome (infra failure) fails closed.
export const check: Check = (delta): CheckResult => {
  const v = delta.post.victim;
  if (v === undefined || v.status !== "abort") return { witnesses: [] };
  const witnessed = /is_left_child/.test(v.message ?? "");
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
