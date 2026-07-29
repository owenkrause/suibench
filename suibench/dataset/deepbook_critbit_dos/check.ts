// Snapshot-pure availability predicate for the permanent-brick critbit DoS. The
// exploit "succeeds" iff the victim traversal V did NOT complete — the confirmer
// folds V's outcome into `delta.post.victim`.
//
// `!== "success"` (NOT gas_exhausted, unlike a loop-DoS): the bug is an out-of-
// bounds ASSERT, so the vulnerable victim op MoveAborts => non-success. The patch
// DELETES that assert, so on the SAME bricked state the victim op SUCCEEDS —
// "not success" cleanly separates bug from patch, and the benign tree succeeds.
import type { Check } from "core";

export const check: Check = (delta) => delta.post.victim?.status !== "success";
