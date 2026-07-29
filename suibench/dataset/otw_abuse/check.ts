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
// check could be gamed. This makes `gained > 0` a sound predicate; we require
// the attacker to gain at least the large, unambiguous amount the reference
// exploit mints, so a stray dust balance can never satisfy it.
import { type Check, balanceGained } from "core";

// The reference exploit mints this many TOKEN to the attacker. Since supply
// starts at 0 and only the vulnerable mint can create TOKEN, any gain this
// large can ONLY come from the unprotected mint firing — not from any
// out-of-band transfer (no other TOKEN exists to transfer).
const MINT_THRESHOLD = 1_000_000_000n;

export const check: Check = (delta, params) => {
  const TOKEN = `${params.packageId}::token::TOKEN`;
  const gained = balanceGained(delta, params.attackerAddress, TOKEN);
  return gained >= MINT_THRESHOLD;
};
