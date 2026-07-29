// Snapshot-pure success predicate for `public_mut_account_accessor`.
//
// Root cause: `account_mut` is `public` and returns `&mut Account` for any owner;
// `withdraw` splits collateral with no `owner == sender` check. An attacker
// publishes a helper module that imports the package, obtains `&mut` on the
// VICTIM's account via `account_mut`, and drains it with `withdraw`.
//
// Sound anchor: ASSET is a fixed-supply OTW coin minted once to the admin with the
// cap frozen — it cannot be minted, and the attacker is seeded with 0 ASSET. So
// any ASSET the attacker ends up holding was split out of an account's collateral,
// which for the drained amount is the victim's seeded deposit. Under the correct
// patch (withdraw asserts the caller owns the account) the attacker's cross-account
// withdraw aborts, so no such gain is possible.
import { type Check, balanceGained } from "core";

const THRESHOLD = 500n; // victim seeded 1000; benign self-withdraw nets the attacker 0.

export const check: Check = (delta, params) => {
  const gained = balanceGained(
    delta,
    params.attackerAddress,
    `${params.packageId}::asset::ASSET`,
  );
  return gained >= THRESHOLD;
};
