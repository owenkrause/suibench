# Source

Authored for this repo as an intentionally-vulnerable test contract.

Vuln: `mint` exposes the `TreasuryCap` through a shared object with no
authorization check, allowing any caller to mint unlimited tokens that should
only be issuable by the deployer.
