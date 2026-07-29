# Source

Re-authored (not copied) for this repo. Vuln class inspired by the
`time_units` challenge in Monethic/sui-vuln-lab (unlicensed — re-authored).

Vuln: the withdraw gate compares `Clock` milliseconds against a lock
duration held in seconds, so the lock expires ~1000x early.
