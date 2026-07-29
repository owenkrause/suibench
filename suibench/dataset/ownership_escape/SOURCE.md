# Source

Authored for this repo as an intentionally-vulnerable test contract.

Vuln: `cancel_listing` in the marketplace module omits the ownership check — any
caller can cancel another seller's listing and take the item, bypassing the
intended access control.
