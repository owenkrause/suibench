// Snapshot-pure availability predicate for the redeem-loop DoS. The exploit
// "succeeds" iff the victim redeem V was denied specifically by GAS EXHAUSTION
// (the non-terminating loop). Keying on gas_exhausted — NOT `!== "success"` —
// is load-bearing: the patch turns an over-redeem into a clean
// ENotEnoughToRedeem abort, which is ALSO non-success. Only the gas-exhaustion
// outcome distinguishes the bug (loop) from the patched abort.
import { type Check, type CheckResult } from "core";

const LABEL_ID = "redeem-infinite-loop" as const;

export const check: Check = (delta): CheckResult => {
  const witnessed = delta.post.victim?.status === "gas_exhausted";
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
