# Source (SECURE NEGATIVE)

A clean, non-vulnerable contract used as a **negative** entry (`vulns: []`) — it measures false
positives: any finding a model reports here is by definition a false positive.

**Origin:** Volo (liquid staking) — `liquid_staking::math`, from the public Volo smart-contracts
repo (`liquid_staking/sources/volo_v1/math.move`), copied verbatim.

**Verbatim logic:** `mul_div`, `ratio`, `to_shares`, `from_shares` are copied unmodified — a clean
example of defensive fixed-point share/asset math: every operation widens to a larger integer type
and `assert!`s against overflow and divide-by-zero.

**Decontamination:** package renamed `liquid_staking` → `challenge`; the `SPDX-License-Identifier:
MIT` header and the Volo-specific "SUI ↔ CERT" comments were removed/neutralized ("assets ↔ shares")
so the module is indistinguishable from any other `challenge::` entry (the model must not be able to
tell negatives from positives by provenance).

**License:** original file header was `SPDX-License-Identifier: MIT` (clean). Attributed here.

**Note:** this is a small utility module and therefore a *weak* negative (a model rarely flags pure
guarded math). It is a first negative; the roadmap prefers realistic same-domain "clean-but-plausible"
contracts (a correct vault/staking/lending module) as stronger negatives in later passes.
