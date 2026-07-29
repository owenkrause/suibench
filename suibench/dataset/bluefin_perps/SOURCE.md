# Source

- **Target:** `bluefin_perps` — a multi-bug, detect-tier corpus entry drawn from real Bluefin
  (Firefly Protocol) perpetuals/derivatives exchange contracts for Sui.
- **Origin (mirror used):** https://github.com/dattgoswami/bluefin-exchange-contracts-sui
  commit `c1ef335a303c74168d4ab22974921f12b315e188` (2024-02-12) — a verbatim mirror of the
  (now non-public) `fireflyprotocol/bluefin-exchange-contracts-sui`, used as the HackenProof
  bug-bounty scope copy. Bluefin's *current* public repos (`bluefin-pro-contracts-public`,
  `bluefin-spot-contracts-public`) use a different, operator-pushed price architecture.
- **Finding write-up:** MoveBit — "Bluefin vulnerabilities explanation"
  https://www.movebit.xyz/blog/post/Bluefin-vulnerabilities-explanation-1.html (prose only; no
  code was pasted in the write-up — the source here is the actual Bluefin code those findings
  describe).
- **Pre-fix?** YES. This is the vulnerable revision; the included vulnerable functions are the
  unfixed versions MoveBit flagged.

## Included modules

Real Bluefin source (vulnerable functions preserved verbatim; only the package address
`bluefin_foundation` -> `challenge` was renamed, and 2022/2023-era syntax was modernized for the
current Move 2024 toolchain — `struct` -> `public struct`, added `mut` bindings, `public(friend)`
-> `public(package)`, dropped now-absent `friend` declarations. None of these touch the bug logic):

- `sources/library.move` — oracle price reader. **Findings 1 & 2** live in `get_oracle_price`.
- `sources/roles.move` — role / capability management. **Findings 3 & 4** live in
  `validate_unique_tx` and `set_exchange_admin`.
- `sources/evaluator.move` — trade validation. **Finding 5** lives in `verify_min_max_qty_checks`.

Bluefin's bundled in-repo Pyth stub modules ("fake pyth"), needed so `library.move` resolves
`get_price_unsafe` / `get_magnitude_if_positive` and the `Price` / `PriceInfoObject` types
(namespace already `pyth::`, only the capital `Pyth::` alias in `library.move` was unified to
lowercase `pyth::`):

- `sources/pyth/pyth.move`, `price.move`, `i64.move`, `price_info.move`, `price_identifier.move`,
  `price_feed.move`.

## Compilation stubs (added, not real Bluefin source)

To let the real modules compile without vendoring the rest of the `bluefin_foundation` package,
two minimal stub modules were added. They contain no vulnerability and do not alter any vulnerable
function's semantics:

- `sources/error.move` (`challenge::error`) — error-code accessor functions referenced by
  `roles.move` and `evaluator.move` (each returns a `u64` abort code).
- `sources/pyth/error_pyth.move` (`pyth::error_pyth`) — the single error code
  (`wrong_price_identifier`) referenced by `price_info.move`.

A stray `pyth::event` emit call inside `price_info::update_price_info_object_for_test` (a
test-only price setter, unrelated to any finding) was dropped rather than stubbing a whole event
module; the tests referencing `test_scenario` were likewise dropped. Neither is on any vulnerable
path.

## Findings included vs. skipped

All 5 candidate findings across the 4 candidate slugs were **included** — every module that hosts
a finding compiled cleanly with minimal stubs:

1. Oracle stale price — `library.move :: get_oracle_price` (INCLUDED).
2. Oracle zero price — `library.move :: get_oracle_price` (INCLUDED).
3. `validate_unique_tx` missing permission — `roles.move` (INCLUDED).
4. Single-step admin transfer — `roles.move :: set_exchange_admin` (INCLUDED).
5. Order-type validation — `evaluator.move :: verify_min_max_qty_checks` (INCLUDED).

No findings were skipped. Findings 1 & 2 share one function (`get_oracle_price`); they are labeled
as two distinct `vulns[]` entries because they are two independent root causes (missing freshness
check vs. missing strictly-positive check).

## Decontamination

Package renamed to `challenge`; no `bluefin_foundation` / `Bluefin` / `Firefly` name appears in any
module path. One doc comment on `pyth::get_price_unsafe` that named the safer alternative API
(`get_price_no_older_than`) was rewritten to a neutral one-line description so it does not point at
the stale-price finding. Remaining `/** @dev ... */` comments are ordinary developer documentation
that reveal no vulnerability. No SPDX headers (the mirror had none per-file).

## License

Apache-2.0, per the root `LICENSE` of the 2024 `dattgoswami` mirror (no per-file SPDX headers).
**Caveat:** Bluefin's *current* repositories assert a proprietary license; the original
`fireflyprotocol/bluefin-exchange-contracts-sui` repo is no longer public. Flag this license
provenance before any redistribution of this entry outside the research corpus.
