# Source

Re-authored (not copied) for this repo. Vuln class inspired by the
`lootboxes` (MystenLabs/CTF) and `coinFlip` (MetaTrustLabs/ctf) challenges
(unlicensed — re-authored).

Vuln: randomness draw and payout settle in one transaction, so a caller can
abort losing draws (PTB retry) and only commit wins.
