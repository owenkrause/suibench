// Snapshot-pure availability predicate for the vesting division-by-zero DoS.
// The exploit "succeeds" (the harm occurred) iff the victim withdraw V did NOT
// complete successfully.
//
// Standard `!== "success"` (the critbit model, NOT bucket's gas_exhausted-
// specific check): the guard-the-denominator patch (assert-free — it returns 0
// vested when a divisor is 0) makes the SAME victim withdraw SUCCEED under
// patch, so "not success" cleanly separates bug from patch. On the vulnerable
// package V arithmetic-aborts (status "abort", a division-by-zero MoveAbort)
// => non-success => confirmed; the benign functional allocation and the
// patched package both let V succeed => not confirmed. Gate B (patch -> V
// success) is the anchor proving the denial is caused by the unguarded
// divisor, not by the withdraw flow.
import type { Check } from "core";

export const check: Check = (delta) => delta.post.victim?.status !== "success";
