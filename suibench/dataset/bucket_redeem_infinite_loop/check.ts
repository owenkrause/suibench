// Snapshot-pure availability predicate for the redeem-loop DoS. The exploit
// "succeeds" iff the victim redeem V was denied specifically by GAS EXHAUSTION
// (the non-terminating loop). Keying on gas_exhausted — NOT `!== "success"` —
// is load-bearing: the patch turns an over-redeem into a clean
// ENotEnoughToRedeem abort, which is ALSO non-success. Only the gas-exhaustion
// outcome distinguishes the bug (loop) from the patched abort.
import type { Check } from "core";

export const check: Check = (delta) => delta.post.victim?.status === "gas_exhausted";
