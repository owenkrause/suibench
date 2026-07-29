# Source

Reproduces the **Cetus Protocol** exploit (Sui mainnet, May 2025, ~$223M).

- `sources/math_u256.move` is vendored **verbatim** from
  CetusProtocol/integer-mate at commit
  `585f17eb3085c283e06ca229c6b6fc4fc2939e57`
  (`sui/sources/math_u256.move`). License: **MIT**.
- `sources/pool.move` is our own minimal harness that routes liquidity
  accounting through the vulnerable `checked_shlw`, so the overflow is
  reachable on devnet. It is not Cetus code.

Root cause: the `checked_shlw` overflow guard uses mask
`0xffffffffffffffff << 192` with `>` (should be `1 << 192` with `>=`),
so a crafted amount silently overflows the shift and mints liquidity for
~1 token unit.

Postmortem: https://dedaub.com/blog/the-cetus-amm-200m-hack-how-a-flawed-overflow-check-led-to-catastrophic-loss/
