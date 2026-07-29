// Snapshot-pure success predicate for `signature_unbound_coin_type`.
//
// Root cause: `sell_pack<COIN>` verifies a server signature over a PackMessage
// that omits COIN, so a signature legitimately issued for a CHEAP sale is replayed
// against `sell_pack<VALUABLE>` to drain the VALUABLE reserve.
//
// VALUABLE is fixed-supply (minted only to the admin at init, cap frozen) and the
// attacker starts with 0 VALUABLE. The Game<VALUABLE> reserve holds 1000. So any
// nonzero attacker VALUABLE gain can only be drained reserve, obtained by the
// cross-coin signature replay. The benign path (functional.ts) sells CHEAP for
// the same signature and nets 0 VALUABLE. Under the patch (coin type bound into
// the signed message) the CHEAP-issued signature no longer verifies for VALUABLE,
// so the replay aborts and the attacker gains 0 VALUABLE.
import { type Check, balanceGained } from "core";

export const check: Check = (delta, params) => {
  const VALUABLE = `${params.packageId}::valuable::VALUABLE`;
  return balanceGained(delta, params.attackerAddress, VALUABLE) >= 500n;
};
