# whitelist_campaign_unbound — Source provenance

Confirmed-tier entry with a pure event checker. It models three independent
launchpad authorization failures: a whitelist unbound from its campaign,
unauthorized whitelist membership mutation, and unauthorized whitelist
creation for another admin's campaign. **Confirmability: `confirmable-value`**
— an attacker gains an allocation in a gated sale (adversary = non-whitelisted
attacker; victim = the campaign's legitimate whitelisted investors).

## Provenance
- **provenance-tier: named-audit** (Major)
- **disclosure-date: 2023–2024** (MoveBit SuiPad audit)
- **Source:** MoveBit — "SuiPad Smart Contract Audit Report", finding **CPG-09 "Lack of Validation for
  Campaign and Whitelist ID in `invest`"** (Major, `sources/campaign.move#L158`). Report text (verbatim):
  "there is no validation that the ID of the campaign and whitelist match, which can allow members of
  other campaigns' whitelists to participate in the current campaign."
- Source repo `SuiPad/suipad-contract` is 404/private → re-authored from the report.
- **Attribution boundary:** A (`whitelist-unbound-campaign`) is re-authored
  from cited CPG-09. B and C are independent authorization gaps identified in
  this re-authored fixture; they are not independently attributed to the
  MoveBit report.

## Relation to sibling entries (class overlap — noted for pruning)
This is the same broad class as `pool_type_index_mismatch` (a pool type and an asset index not validated
to correspond) and `generic_type_unbound_upgradecap` (a request not bound to a generic State's type):
"two related things passed independently, their binding never checked." It is kept as a distinct entry
because the code, the objects involved (two shared objects: campaign + whitelist), the check that's missing
(`whitelist.campaign_id == object::id(campaign)`), and the impact (access-gate bypass on a launchpad sale,
not value theft) all differ. If three instances of this class is too many, this is the one to prune.

## Vulnerabilities
`invest(campaign, whitelist, payment, ...)` asserts the sender is in `whitelist.members` but not that
`whitelist.campaign_id == object::id(campaign)`. An attacker on any campaign's whitelist passes that
whitelist with a different campaign and invests in a sale they were never whitelisted for.

`add_member(whitelist, member, ...)` does not require the sender to be the
whitelist's recorded admin, so an attacker can add themselves to the admin's
campaign whitelist. `create_whitelist(campaign, ...)` does not require the
sender to be `campaign.admin`, so an attacker can create and administer a new
whitelist that is correctly bound to the victim campaign.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED** from the MoveBit finding — a minimal launchpad with shared `Campaign` and `Whitelist`
  objects (the whitelist records `campaign_id` and its creating `admin`), permissive authorization
  boundaries, and an `allocations` table so each illicit allocation is concrete.

## Decontamination
- Package/address `challenge`; module `launchpad`. No vuln/audit/fix-naming comments in `sources/` (the bug
  is the absent `campaign_id` check in `invest`). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
