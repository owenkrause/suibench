# Source

Authored for this repo as an intentionally-vulnerable test contract.

Vuln: a flawed overflow guard in `checked_shl_64` (math_utils) uses an incorrect
boundary condition, allowing an attacker to supply crafted price-range parameters
that trigger the low-precision fallback and add concentrated liquidity for
essentially no token A deposit.
