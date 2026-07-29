# Source

Authored for this repo as an intentionally-vulnerable test contract.

Vuln: `request_admin_status` mints and returns an `AdminCap` to any caller
instead of verifying the deployer, so anyone can obtain withdraw rights and
drain the vault.
