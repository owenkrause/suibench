// Snapshot-pure success predicate for `whitelist_campaign_unbound`.
//
// Root cause (module `launchpad`): `invest(campaign, whitelist, payment, ctx)`
// asserts the sender is in `whitelist.members` but NEVER asserts
// `whitelist.campaign_id == object::id(campaign)`. An attacker whitelisted only
// on their OWN campaign B passes campaign A (a gated sale they were never
// whitelisted for) together with Whitelist_B; the membership check passes
// against the WRONG list and `invest` commits the attacker's SUI payment into
// campaign A's `raised` balance and records an allocation for them.
//
// Confirmability note: this is an access-gate BYPASS, not value theft. The
// attacker does not RECEIVE value; they PAY real SUI into a gated sale that the
// patched contract would reject. Campaign and Whitelist are SHARED objects, so
// their state (the illicit `allocations` entry, `raised`) is not in the
// address-owned confirmer snapshot. The only snapshot-observable signature of a
// committed `invest` is therefore the attacker's SUI outflow into the launchpad
// Campaign balance. The predicate keys on that with TWO clauses:
//
//   (1) EFFECT — the attacker committed a real `invest` payment: their SUI
//       balance fell by at least the sale payment (~PAYMENT). Under the PATCHED
//       build `invest(campaignA, whitelistB)` aborts (EWrongCampaign) BEFORE the
//       transaction is submitted, so the attacker's SUI delta is 0 and this
//       clause is false — i.e. the pass is reachable ONLY when the mismatched
//       pair is accepted, which is exactly the labeled bug.
//   (2) MECHANISM ANCHOR — `launchpad::invest` sinks the payment into the SHARED
//       `Campaign.raised` Balance, NOT into another account. So the SUI the
//       attacker lost must NOT reappear in any funded peer (admin or user). This
//       rules out the out-of-band path the gold standard warns about — an
//       attacker simply transferring SUI to a funded keypair to fake a balance
//       move — and pins the outflow to a Move payment sink. During the attack
//       phase only the attacker transacts, so on the true `invest` both peer
//       deltas are 0; a peer-transfer forgery would credit a peer instead.
import { type Check, balanceGained } from "core";

/** Canonical SUI coin type. */
const SUI = "0x2::sui::SUI";
/** The exploit pays this into the gated campaign (see exploits/…: 1_000_000n). */
const PAYMENT = 1_000_000n;
/** Slack below PAYMENT; the committed outflow is PAYMENT + gas, always >= PAYMENT. */
const LOSS_EPSILON = 10_000n;
/** A funded peer must not have absorbed the payment — it went to the shared Campaign. */
const PEER_GAIN_CAP = PAYMENT / 2n;

export const check: Check = (delta, params) => {
  if (!params.adminAddress || !params.userAddress) return false;

  // Clause (1): the attacker committed a real invest payment (SUI outflow >= ~PAYMENT).
  // Patched `invest(A, whitelistB)` aborts pre-submission -> attacker delta 0 -> false.
  const attackerLoss = -balanceGained(delta, params.attackerAddress, SUI);
  if (attackerLoss < PAYMENT - LOSS_EPSILON) return false;

  // Clause (2): the lost SUI went into the launchpad Campaign, not to a funded
  // peer. Neither admin nor user may have absorbed it.
  if (balanceGained(delta, params.adminAddress, SUI) > PEER_GAIN_CAP) return false;
  if (balanceGained(delta, params.userAddress, SUI) > PEER_GAIN_CAP) return false;

  return true;
};