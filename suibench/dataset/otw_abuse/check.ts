// Snapshot-pure success predicate for `otw_abuse`.
//
// Root cause: `token::mint` (sources/token.move) takes the shared
// `TreasuryCapHolder` by `&mut` and mints against its wrapped `TreasuryCap`
// with NO access-control gate, so ANY account can issue arbitrary TOKEN to any
// recipient. `init` starts the currency at supply 0 and performs no initial
// mint, and `mint` is the ONLY function in the module that can create TOKEN.
//
// Soundness — the conserved-supply-at-zero invariant. TOKEN is a custom coin
// whose total supply begins at exactly 0 and whose ONLY mint source is the
// vulnerable `mint`. There is no faucet, no init distribution, and no way to
// obtain TOKEN out-of-band (the provided admin/user/attacker keypairs hold
// zero TOKEN and cannot transfer what does not exist). Therefore ANY positive
// attacker-held TOKEN balance is proof that the ungated mint fired — it cannot
// arise from a keypair-to-keypair transfer the way a native/SUI `balance > 0`
// check could be gamed. This makes `gained > 0` a sound predicate: the smallest
// valid exploit — minting a single unit — is as much proof as the reference
// mint. Anchoring the threshold to the reference mint (1e9) would REJECT that
// smaller-but-sound exploit; the fixed-supply-at-zero invariant is the true
// anchor, so the floor is one unit. Gas is paid in SUI, not TOKEN, so no
// epsilon is needed — the abused-type gain is an exact integer.
//
// Measured (Confirmer over Docker): vulnerable reference mints 1e9, the
// single-unit variant yields exactly 1; the gold OTW/admin-gated patch aborts
// the mint so the attacker gains 0 on every variant. `1n` sits cleanly between
// the patched ceiling (0) and the smallest valid exploit (1).
import { type Check, type CheckResult, balanceGained } from "core";

const LABEL_ID = "unprotected-mint" as const;

// One unit of the abused type. Supply starts at 0 and the vulnerable mint is
// the only TOKEN source, so any gain >= this (i.e. > 0) can ONLY come from the
// ungated mint firing — never from an out-of-band transfer (no TOKEN exists to
// transfer). The patched build blocks the mint entirely (measured ceiling: 0).
const MINT_THRESHOLD = 1n;

export const check: Check = (delta, params): CheckResult => {
  const TOKEN = `${params.packageId}::token::TOKEN`;
  const gained = balanceGained(delta, params.attackerAddress, TOKEN);
  const witnessed = gained >= MINT_THRESHOLD;
  return { witnesses: witnessed ? [LABEL_ID] : [] };
};
