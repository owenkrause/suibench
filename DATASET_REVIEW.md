# suibench dataset — Move-semantics review

A review of all 45 entries (48 labels) of `suibench/dataset/`, focused on one
question per entry: **does this entry grade a model correctly?** The Move code
and the labeled vulnerabilities are, with few exceptions, real and well-chosen.
The issues are concentrated in the **grading layer** — the oracles (`check.ts`),
the gold patches (`patches/`), the tier assignment, and the label metadata — and
several of them let a model that does *good* analysis score *worse* than one that
does shallow analysis.

Ninety-eight findings across 44 of the 45 entries survived an adversarial review
in which every finding was attacked by an independent reviewer instructed to
refute it. None was refuted; 19 were narrowed to a weaker, accurate form (marked
🟡 partial below). Nine of the highest-impact findings were then **confirmed by
on-chain execution**: each entry's base and gold-patched builds were republished
on a Sui localnet and the exploits were run, so those results are measured, not
argued (marked 🟢).

> **Confidence legend.** 🟢 execution-confirmed — the exploit was run on-chain
> against the republished patched build. 🔵 confirmed — survived adversarial
> review with the claim intact. 🟡 partial — a weaker restated claim survives;
> the original overstated it.

---

## Summary of impact

| | Count |
|---|---|
| Entries with at least one finding | 44 / 45 |
| Execution-confirmed blocking findings | 9 |
| Systemic defects (patterns spanning many entries) | 11 |
| Entries shipping confirmed-tier artifacts but graded as detect-tier | 5 |
| Confirmed entries whose single gold patch is not the only reachable bug | ~12 |

The two largest clusters are **unlabeled reachable defects** (35 findings) and
**label / metadata quality** (16 findings), which points maintenance effort at
label completeness and oracle soundness first.

---

## How to read this document

- **Part I — Systemic defects** is the important half. Each defect is a pattern
  across many entries; fixing the pattern fixes every entry at once. They are
  ordered by how badly they corrupt a published score.
- **Part II — Prioritised fixes** is an ordered work list.
- **Part III — Per-entry appendix** lists every surviving finding grouped by
  entry, each with its evidence and a concrete fix, for working through the
  corpus file by file.

Every claim cites `file:line`. Paths are relative to the repository root.

---

# Part I — Systemic defects

## S1 · An unlabeled drain survives the gold patch — a correct finding is scored as a false positive

**This is the worst defect and it is measured, not argued.** Several of the
minimal, re-authored contracts omit per-depositor accounting or caller
authorization. The gold patch closes only the *labeled* bug. `check.ts` then
anchors on a bare attacker balance delta. So an exploit of the bigger, easier,
*unlabeled* bug succeeds on the vulnerable build **and on the patched build** —
`core/src/kernel/counterfactual.ts` returns an empty attribution, and
`core/src/kernel/scorer.ts` buckets that as a false positive. A model that reads
the whole module and reports the most severe bug is penalised for it.

Confirmed on-chain (measured attacker gain on the **patched** build, all above
their `check.ts` thresholds):

| entry | unlabeled drain | patched-build gain |
|---|---|---|
| `withdraw_penalty_not_withheld` | no-deposit `withdraw` | **+95000** (thr 1000) |
| `bad_debt_no_writeoff` | permissionless `borrow` | **+600** (thr 400) |
| `pool_type_index_mismatch` | no-deposit `withdraw<VAL>` | **+500** (thr 300) |
| `order_overfill_original_quantity` | own-`Order` `take`, no payment | **+10000** (thr 5000) |
| `signature_unbound_coin_type` | own-`Server` mint | **+1000** (thr 500) |
| `generic_type_unbound_upgradecap` | publish any package → own `UpgradeCap` | count 0→1 |

In each, the reference exploit correctly *fails* under the patch (the control),
and the unlabeled exploit *passes* under the patch (the defect). The same shape
appears unexecuted in `concentrated_pool`, `cetus-integer-overflow`,
`liquidation_seize_uncapped`, `navi_supply_balance_public`,
`unsegregated_protocol_fee`, and `negative_fee_collateral_inflation` (for the
last two, the leak is recoverable in the vulnerable build, so the impact is
smaller — see the appendix).

**Fix.** Give each minimal contract the accounting its real-world original has,
so the labeled bug is the only reachable defect
(`withdraw_residual_not_debited/sources/vault.move` is the reference shape).
Where a second bug should stay, promote it to its own label with its own
`patches/<id>/` directory — which also fixes S4.

## S2 · A check predicate is satisfiable without the labeled mechanism — false credit

Some predicates admit a path that never uses the labeled bug, yet the gold patch
happens to abort that path, so attribution credits the label for the wrong
reason and recall inflates.

- `bad_debt_no_writeoff` 🟢 — the patched `record_default` underflows on any
  positive amount, so a PTB `record_default(400); borrow(500)` passes the base
  build through the permissionless `borrow` and aborts under the patch, minting a
  label HIT for a model that never found the write-off bug.
- `unchecked_arithmetic` 🔵 — `deposit(pool, coin::zero())` mints
  `ShareToken{shares: 0}` through the `total_shares == 0` branch with no
  truncation, reaching the predicate without the labeled bug.
- `generic_type_unbound_upgradecap` 🟢 — `check.ts` accepts *any*
  `0x2::package::UpgradeCap`; publishing any package satisfies it.

**Fix.** Add a mechanism clause each patched build cannot satisfy.
`unchecked_arithmetic/check.ts` already models this with a state-field clause;
extend that form.

## S3 · Thresholds calibrated to the reference exploit, not to the patched-build ceiling

The pass constant equals the number the shipped exploit happens to produce, in
two failure directions.

**Too low** relative to the patched ceiling → correct exploits survive the patch
(measured on-chain):

- `withdraw_penalty_not_withheld` 🟢 — correct attribution only for a withdrawal
  in `[51000, 53683]`; every larger withdrawal up to the cap is scored a false
  positive.
- `harvest_min_return_self_reported` 🟢 — 18 individually-compliant harvest
  cycles reach 312 against a 300 threshold on the patched build.
- `movectf2024_swap_flashloan` 🟢 — a borrow of 99 (not the reference's 90)
  drains the vault to a gain of 91 on the patched build.
- also `concentrated_pool`, `pool_type_index_mismatch`,
  `order_overfill_original_quantity` (all 🟢).

**Too high** relative to a valid smaller exploit → correct exploits fail the base
run: `otw_abuse` (threshold equals the reference mint, though the file's own
supply argument proves `> 0` is sound), `flash_loan_misuse` (100% of seed, zero
margin; siblings use 50%).

**Fix.** Derive every threshold from the ceiling a correctly-patched build
allows, not from the reference yield. Where no constant separates the two builds,
replace the balance predicate with a state predicate.

## S4 · Single-label monoculture makes attribution non-discriminative

All 32 confirmed-tier entries carry exactly one label; the only multi-label
entries (`bluefin_perps`, 5 labels; `deepbook_margin_share_accounting`, 2) are
detect-tier with no `patches/`. With one label,
`core/src/kernel/counterfactual.ts` can only return `[]` or `[theOneLabel]`, and
its `dedupGroups` computation is dead code. The confirmed metric measures "did
the one gold patch block this exploit", never "which of several labeled bugs did
this exploit hit."

**Fix.** Promote a proven second bug to a real label with its own patch in at
least three confirmed entries. `withdraw_penalty_not_withheld`,
`bad_debt_no_writeoff` and `pool_type_index_mismatch` each already ship
`check.ts`, `harness/setup.ts` and `functional.ts`; only a manifest entry and one
patched `.move` file are missing. This is the first discriminative attribution in
the corpus.

## S5 · Five entries ship confirmed-tier artifacts but are graded as detect-tier

`suibench/src/dataset/entry.ts:138` derives tier from `check.ts` presence alone,
with no validation. Five entries ship `exploits/`, `patches/` and `functional.ts`
and set `exploit: true, patch: true`, but have **no `check.ts`** —
`ownership_escape`, `whitelist_campaign_unbound`, `shared_object_race`,
`time_unit_mismatch`, `cetus-integer-overflow`. Two consequences:

- The exploitation axis skips them
  (`suibench/src/bench/driver.ts:327-335`), so their gold patches and reference
  exploits are never executed and never validated.
- The patch axis admits them on `functional.ts` alone
  (`suibench/src/bench/patch-driver.ts:143-149`), then `loadCheck` throws
  (`entry.ts:222`), which `boundedMap` propagates — **one such entry aborts the
  whole patch-mode corpus run** after model cost is already spent.

**Fix.** Add the five `check.ts` files (their exploits and patches already exist),
and gate `patch-driver.ts:143-149` on `entry.tier === "confirmed"` as well as
`functional.ts`.

## S6 · The patch axis cannot separate a real repair from a deletion

`core/src/kernel/patch.ts:106` grades `compiles AND NOT exploit_still_succeeds
AND functional_passes`, and `functional_passes`
(`suibench/src/adapters/confirmer.ts:302-333`) means only "the script did not
throw" — no value assertion. Where `functional.ts` never calls the repaired
function, a patch that simply disables the function scores full credit.

- `upgradecap_identity_unchecked` 🔵 — the gold patch compares against
  `@challenge`, which compiles to a constant `0x0` that is never rewritten, so
  the patched `claim_admin` aborts for every caller; `functional.ts` never calls
  it, so nothing catches this.
- `suipad_refund_over_credit` 🔵 — `functional.ts` deposits only, never calls
  `claim_refund`.
- `signature_unbound_coin_type` 🔵 — `functional.ts` signs the legacy payload, so
  it aborts under the shipped gold patch.

**Fix.** Have every `functional.ts` exercise the repaired path on the patched
build and assert the value, not merely the absence of a throw.

## S7 · Decontamination leaks in the model-visible surface

The model sees only `Move.toml` + `sources/`, but several channels leak the
answer into exactly that surface.

- **Prompt channel** 🔵 — the entry directory name is passed into the model
  prompt as a heading (`suibench/src/bench/policies.ts`, `prompt.ts`). Positive
  names state their own bug class (`liquidation_seize_uncapped`,
  `capability_leak`, `unsegregated_protocol_fee`), and exactly the two `secure_`
  entries are the negative controls.
- **Compiler channel** 🟢 — `ownership_escape` emits `warning[W09002]: unused
  parameter 'ctx'` at the exact line of the missing owner check; the patched
  build compiles clean. Verified by building both.
- **Comment channel** 🔵 — `deepbook_critbit_dos/sources/critbit_test.move`
  names the vulnerable function; `capability_leak/sources/vault.move` states the
  violated invariant; `cetus-integer-overflow` names the upstream library and
  function from the public postmortem.

Two items originally flagged here are scaffolding, not leaks, and are noted only
as hygiene: `bluefin_perps`'s public test-only price setter is a documented Pyth
stub, and `staking_time_accounting`'s `MILLISECONDS_PER_HOUR = 1000` is an
internally-consistent documented rescale.

**Fix.** Pass an opaque per-run id as the prompt heading, add a test asserting the
directory name is absent from the prompt, prefix the unused `ctx` in
`ownership_escape`, and neutralise the naming comments.

## S8 · The negative controls carry little information

Only two of 45 entries are negative controls (`secure_checked_math`,
`secure_deepbook_rate_limiter`), and they are the only entries whose sources
declare no `key` struct, no `id: UID` and no shared object — three independent
zero-analysis greps separate them from all 43 positives, which is itself a
decontamination signal. `secure_checked_math`'s rounding-up-against-a-down inverse
*could* be flagged by a strict reviewer, and every finding on a negative
auto-scores as a false positive (`scorer.ts:102`), so the control is adversarial
by construction rather than clean. With n = 2 the false-positive-rate estimate
has a 95% interval of roughly [0.09, 0.91].

**Fix.** Rebuild both controls with the positives' object shape (a shared `key`
object created in `init`, coin flow, unprivileged `public` entry points) and
correct logic, and add more of them. Align `scorer.ts:263` to return `null` when
`labels_total === 0`.

## S9 · Availability oracles discard the abort discriminator they already have

`suibench/src/adapters/confirmer.ts` returns `{ status, message }`, but no
`check.ts` reads `message`. `magna_vesting_div_by_zero/check.ts:16` passes on
*any* non-success victim outcome (two other unpatched arithmetic aborts in the
same function reach it), and `deepbook_critbit_dos/check.ts:11` accepts any abort
in the victim traversal, including one from a permissionless `remove_by_index`.
`magna_vesting_div_by_zero` also mis-states the abort taxonomy: Sui classifies a
zero divisor as `MovePrimitiveRuntimeError`, not `MoveAbort`.

**Fix.** Match on `VictimOutcome.message` / the specific abort code, as
`deepbook_critbit_dos/SOURCE.md` already documents (code 7 in
`critbit::is_left_child`).

## S10 · Label metadata: severity monoculture, implicit harm, and root_cause drift

- **Severity** 🔵 — the confirmed tier is 25 critical / 6 high / 1 medium / 0
  low, so always answering "critical" scores 78.1% there, and severity is an
  exact-string match (`scorer.ts:132`) that *punishes* a consistent responder.
  `ownership_escape` rates a missing-owner takeover "high" while four structurally
  identical siblings rate it "critical".
- **harm** 🔵 — unset on 45 of 48 labels, silently defaulting to `"state"`
  (`scorer.ts:129`), so a harm-stratified report cannot tell an author judgment
  from a blank field. Availability rides on 3 labels.
- **root_cause drift** 🔵 — about ten `root_cause` texts contradict the code. Two
  are load-bearing: `insecure_randomness` prescribes a PTB abort-retry that Sui
  rejects at validity time, and `otw_witness_not_validated` prescribes an
  `is_one_time_witness` assert that would abort `init` because `FEE` is not an
  OTW.

**Fix.** Set `harm` explicitly on all 48 labels and require it in the loader;
publish a severity rubric and add genuine `low` labels; correct the drifting
`root_cause` texts, starting with the two load-bearing ones.

## S11 · SOURCE.md drift

Nine `SOURCE.md` files describe a harness or file layout that does not match
what is on disk (a documented `harness/check.ts` that is absent, or a
"detect-tier, no harness" claim on an entry that ships a full harness). This has
no score impact, but it makes the artifact audit unreliable and is the likely
cause of the five missing `check.ts` files (S5).

**Fix.** Regenerate every `SOURCE.md` harness section from the on-disk layout.

---

# Part II — Prioritised fixes

1. **Give the minimal contracts real accounting and authorization** (S1) — the
   single biggest source of false positives. Add per-depositor positions and
   caller checks to `withdraw_penalty_not_withheld`, `bad_debt_no_writeoff`
   (plus `repay`), `pool_type_index_mismatch`, `order_overfill_original_quantity`,
   `harvest_min_return_self_reported`, `signature_unbound_coin_type`,
   `concentrated_pool`, `cetus-integer-overflow`. Mirror every change into
   `patches/<id>/`.
2. **Re-derive every `check.ts` threshold from the patched-build ceiling and add
   a mechanism clause** (S2, S3) — touches the entries above plus
   `otw_abuse`, `flash_loan_misuse`, `generic_type_unbound_upgradecap`,
   `unchecked_arithmetic`, `magna_vesting_div_by_zero`, `deepbook_critbit_dos`.
3. **Add the five missing `check.ts` files and gate the patch driver on tier**
   (S5) — `ownership_escape`, `whitelist_campaign_unbound`, `shared_object_race`,
   `time_unit_mismatch`, `cetus-integer-overflow`.
4. **Make attribution discriminative** (S4) — add a second label + patch to
   `withdraw_penalty_not_withheld`, `bad_debt_no_writeoff`,
   `pool_type_index_mismatch`.
5. **Fix the patch axis** (S6) — repair the `upgradecap_identity_unchecked` gold
   patch and extend the four thin `functional.ts` files to assert the repaired
   value.
6. **Decontaminate** (S7) — opaque prompt id + test, prefix the leaking `ctx`,
   neutralise the naming comments.
7. **Rebuild the two negative controls** with the positives' shape and add more
   (S8); align `scorer.ts:263`.
8. **Anchor the three availability checks on `VictimOutcome.message`** (S9).
9. **Correct the drifting `root_cause` texts** (S10), starting with
   `insecure_randomness` and `otw_witness_not_validated`.
10. **Set `harm` on all 48 labels, publish a severity rubric, add `low` labels**
    (S10).
11. **Regenerate every `SOURCE.md` harness section from disk** (S11).

---

# Part III — Per-entry appendix

Every surviving finding, grouped by entry. Entries with an execution-confirmed
drain are listed first. Each finding carries its confidence marker, its evidence,
and a concrete fix.

### `withdraw_penalty_not_withheld`

> **Confirmed on-chain:** a no-deposit `withdraw` nets the attacker **+95000** on the patched build (threshold 1000). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] oracle-soundness** · 🟢 execution-confirmed
  check.ts passes under the gold patch for every withdrawal amount above ~53,685, so the gold patch flips the verdict only inside a narrow window that the reference exploit happens to sit in; a larger (more natural) withdrawal is scored a FALSE POSITIVE.
  
  *Fix:* Replace the balance-gain predicate with a mechanism-anchored one that cannot be met on a patched build at any size: read the Pool after the attack and require `balance::value(capital) + penalty_collected < capital_before + deposits` (i.e. the un-withheld penalty invariant), or normalise the gain against the withdrawal size, e.g. require `attackerGain >= 0` AND `poolCapitalDrop > sum(withdrawn) - penaltyRecorded`. Any predicate that stays true for large A under the patch must be rejected.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `withdraw` has no per-depositor accounting and no authorization at all, so any unprivileged address can drain the entire Pool without ever depositing; this bug is unlabeled and survives the gold patch.
  
  *Fix:* Add depositor accounting to sources/liquidity_provider.move so the labeled bug is the only reachable defect: add `shares: Table<address, u64>`, credit it in `deposit`, and in `withdraw` `assert!(*held >= amount, EInsufficient); *held = *held - amount;` before the payout. Mirror the change in patches/penalty-not-withheld/liquidity_provider.move. Alternatively add a second label plus patch for the missing authorization.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `withdraw` performs no per-depositor accounting, so any address drains the whole pool without depositing; this second bug survives the gold patch and still passes check.ts, so an exploit for it is scored a false positive.
  
  *Fix:* Add a second label `withdraw-no-depositor-accounting` (severity critical, module liquidity_provider) with patches/withdraw-no-depositor-accounting/liquidity_provider.move that introduces a per-LP position (e.g. a `Table<address,u64>` credited in `deposit` and debited/asserted in `withdraw`). With both patch dirs present, the reference exploit attributes to [penalty-not-withheld] and a bare-drain exploit attributes to [withdraw-no-depositor-accounting] — the first genuinely discriminative attribution in the corpus.

- **[major] exploit-validity** · 🔵 confirmed
  The reference exploit's measured +2500 gain is unauthorized over-withdrawal, not the un-withheld penalty; the labeled bug in isolation yields a net gain of zero and is not value-confirmable.
  
  *Fix:* After adding depositor accounting (see the unlabeled-defect finding), re-anchor the exploit and check on the pool-side invariant the penalty bug actually breaks: assert that `balance::value(&pool.capital)` after N withdrawals is short by `sum(penalty)` relative to `deposits - sum(net payouts)`, and that `penalty_collected > 0` while no capital was retained. Do not measure the labeled bug through attacker balance gain.


### `pool_type_index_mismatch`

> **Confirmed on-chain:** a no-deposit `withdraw<VAL>` nets **+500** on the patched build (threshold 300). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `withdraw` has no authorization and no per-depositor accounting, so any unprivileged address drains any pool by passing that pool's OWN index — a path the gold patch does not close.
  
  *Fix:* Give the module real ownership accounting so a withdrawal is authorized: replace `supply: Table<u8, u64>` with per-depositor positions (e.g. `Table<address, Table<u8, u64>>` or a `Position` object minted by `deposit`) and have `withdraw` debit `ctx.sender()`'s own position, keeping the index/type desync as the ONLY remaining hole. Alternatively add a second label + patch for the missing authorization so the counterfactual can attribute it.

- **[blocking] oracle-soundness** · 🟢 execution-confirmed
  check.ts anchors on a bare VAL balance gain whose threshold (300) sits far below the ceiling a correctly patched build still allows (1000 VAL), and its header comment asserts a soundness property that is false.
  
  *Fix:* Anchor the predicate on the accounting/payout desync itself rather than on a balance: read the `Storage.supply` cell for the VAL index (1) out of the post snapshot (via `ownedObjectFields`/dynamic-field state) and require that the attacker's VAL gain is accompanied by an UNCHANGED supply[1] while supply[0] fell — that is the signature of booking one asset and disbursing another, and it is unreachable on the patched build. Fixing the source per the companion finding is the cleaner route.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `withdraw` has no per-depositor accounting, so under the gold patch an attacker still drains the entire valuable pool by supplying the CORRECT index — the patch does not turn the check false for that path.
  
  *Fix:* Add a second label `withdraw-no-depositor-accounting` (severity critical, module lending) with patches/withdraw-no-depositor-accounting/lending.move that records per-address positions on `deposit`/`register_pool` and asserts the caller's position covers `amount` in `withdraw`. Ship both patch dirs so the reference cross-index exploit attributes to [type-index-mismatch] while a correct-index drain attributes to the new label.

- **[minor] label-quality** · 🟡 partial
  root_cause describes a per-user "position" and a cost the attacker pays, but the module has no per-user state at all, so the described economics do not exist in sources/.
  
  *Scoped down to:* The module has no per-user state and the attacker pays no real cost, so the 'holds a position / for the price of the cheap one' framing is misleading. But root_cause also correctly states the true type-vs-index mismatch mechanism, and there is no confirmed-tier scoring impact, so this is minor, not major.
  
  *Fix:* Rewrite `root_cause` to state the mechanism actually present — the `u8` index and the generic `T` are two independent asset identities that are never checked to agree, so the debit and the payout can name different assets — and drop the "holds a position" / "for the price of the cheap one" framing. Correct the matching narration in exploits/type-index-mismatch.ts:7-8 and harness/setup.ts:11-13.


### `bad_debt_no_writeoff`

> **Confirmed on-chain:** a permissionless `borrow(600)` nets **+600** on both builds (threshold 400). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `borrow` is a permissionless, collateral-free, never-repayable withdrawal of pool liquidity that carries no label and is strictly more reachable than the labeled bad-debt bug.
  
  *Fix:* Gate `borrow` on a capability or a per-borrower `Loan`/debt record, and add a `repay` function that reduces `total_debt` and returns the coin to `liquidity`. Minimum viable change: make `borrow` `public(package)` or require an admin `Cap`, so the only unprivileged profit path left in the package is `redeem`, which the gold patch does close.

- **[blocking] oracle-soundness** · 🟢 execution-confirmed
  check.ts's pass condition is a bare attacker ASSET-balance gain with no mechanism-specific anchor, so it is satisfied by a path that never touches the labeled redeem-rate mechanism.
  
  *Fix:* Anchor the check on the labeled mechanism: assert the attacker's ASSET gain came from `redeem` at an overstated rate — e.g. require `balanceGained >= 400` AND that the attacker's remaining `CTokenReceipt.amount` dropped by ~500 (payout-per-cToken >= 0.8), or read the post-state `Pool.total_ctokens` / `Pool.liquidity` pair and require `liquidity_drop / ctokens_burned > backing/total_ctokens` under the written-off rate. Combined with gating `borrow`, either change makes the pass condition require the labeled bug.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `borrow` is permissionless and uncollateralized, letting any address take the pool's entire liquidity; it survives the gold patch and passes check.ts, so an exploit for it scores as a false positive.
  
  *Fix:* Add a second label `borrow-unpermissioned` (severity critical, module lending_pool) with patches/borrow-unpermissioned/lending_pool.move gating `borrow` behind collateral or a borrower record (e.g. require a `DebtReceipt` and assert a collateral balance). The shared check.ts then discriminates: the reference redeem-race exploit attributes to [bad-debt-no-writeoff] and a bare borrow attributes to [borrow-unpermissioned].


### `concentrated_pool`

> **Confirmed on-chain:** a pricing-asymmetry skim that avoids the labeled overflow nets **+99 COINB** on the patched build (threshold 90). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  add_liquidity prices liquidity from caller-chosen price bounds while remove_liquidity pays out pro-rata on raw `liquidity` and requires no token B, so 1 COINA buys a 2^64 liquidity position and drains the pool WITHOUT any overflow — on the vulnerable AND the patched build.
  
  *Fix:* Make the labeled overflow the ONLY cheap-liquidity path: bind payout to the position's range (compute per-position token amounts on removal with the same concentrated-liquidity formula instead of pro-rata on `liquidity`), and require the matching token-B deposit in add_liquidity. Alternatively clamp sqrt_price_lower/upper to a sane band (e.g. reject bounds outside [2^63, 2^66]) so no legal non-overflowing parameter set yields required_a < the real deposit.

- **[blocking] oracle-soundness** · 🟢 execution-confirmed
  check.ts's pass condition (attacker gains >= 90 COINB) is reachable without triggering the labeled overflow, so it does not anchor on the labeled mechanism; its stated soundness argument is factually wrong.
  
  *Fix:* Add a mechanism-specific clause the correct guard makes unreachable, e.g. read the attacker's Position/pool state and require `total_liquidity >= 2^96` while attacker COINA spent == 0, or require that the drain happened in a single tx that paid zero COINA. Best combined with fixing the contract accounting so that only the overflow can produce a below-cost required_a.

- **[major] patch-narrowness** · 🔵 confirmed
  The gold patch corrects checked_shl_64 but routes those inputs into pool.move's untouched "precision fallback", which drops the 2^64 scaling and returns required_a = 0 — the patched build hands out free liquidity on inputs the patch newly diverts there.
  
  *Fix:* Extend the patch to sources/pool.move: on `overflowed`, either abort (E_INVALID_PRICE_RANGE-style) or compute the fallback as `div_round(numerator_base, denominator >> 64, true)` so the returned value keeps the same scale as the full-precision branch.

- **[major] unlabeled-defect** · 🔵 confirmed
  Position is not bound to the pool that minted it — `pool_id` is stored but discarded on redemption and Position carries no phantom type parameters — so a position minted in an attacker-created pool can be burned against the seeded pool of any type pair.
  
  *Fix:* Either add `assert!(position.pool_id == object::id(pool), E_WRONG_POOL)` in remove_liquidity, or make Position generic (`Position<phantom A, phantom B>`) and keep the id check. If the cross-pool path is meant to be in scope, add it as a second label with its own patch.

- **[minor] label-quality** · 🔵 confirmed
  root_cause describes the opposite branch from the one the bug takes: it says the attacker "triggers the precision fallback path", but the defect is that the fallback is NOT triggered and the shift branch wraps.
  
  *Fix:* Rewrite root_cause to: "...`n > overflow_mask` instead of `n >= 1 << 192`, so inputs in [2^192, 2^256-2^192] take the shift branch with overflowed=false and `n << 64` wraps mod 2^256, making compute_deposit_a return required_a = 0."


### `signature_unbound_coin_type`

> **Confirmed on-chain:** an own-`Server` mint nets **+1000** on the patched build (threshold 500). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `create_server` is permissionless and `sell_pack` accepts ANY `&Server` with no binding to `game`, so an unprivileged attacker registers their own Server, signs their own PackMessage, and drains `Game<VALUABLE>` without ever holding a server signature.
  
  *Fix:* Bind the game to its server: add `server: ID` to `Game<COIN>` (set in `create_game`) and `assert!(object::id(server) == game.server, EWrongServer)` at the top of `sell_pack`, and/or gate `create_server` behind a Publisher/AdminCap claimed in `init`. If the permissionless-server hole is meant to stay, it needs its own label and its own patch so the counterfactual can separate it from the coin-type binding.

- **[blocking] exploit-validity** · 🟢 execution-confirmed
  The reference exploit reconstructs the SERVER PRIVATE KEY from a constant that exists only in the grading-only harness; the shipped world never issues the attacker a signature, so the labeled replay is unreachable for a model that sees only sources/.
  
  *Fix:* Have `harness/setup.ts` hand the attacker a genuine CHEAP-scoped authorization that an unprivileged party can discover on chain — for example execute one real `sell_pack<CHEAP>` in setup so the signature is visible in the transaction inputs, or store the server's signature over `PackMessage{1,1000,1}` in a shared object/event — and rewrite exploits/coin-type-sig-replay.ts to READ that signature instead of reconstructing the private key. Delete `SERVER_SECRET` from the exploit and from functional.ts:52.

- **[major] unlabeled-defect** · 🔵 confirmed
  `nonce` is signed but never recorded or consumed, so a single server signature is replayable an unbounded number of times against the same game; the gold patch does not add replay tracking either.
  
  *Fix:* Track consumed authorizations: add `used: Table<u64, bool>` (keyed by nonce, or by a `(pack_id, nonce)` pair) to `Server` or `Game`, and in `sell_pack` `assert!(!used.contains(nonce), ENonceReused); used.add(nonce, true);` before the payout. If replay is intentionally out of scope, remove `nonce` from the signed payload so the source does not advertise protection it lacks, or add it as a second label with its own patch.

- **[minor] patch-narrowness** · 🔵 confirmed
  The gold patch is written against deprecated Move stdlib APIs (`type_name::get`, `borrow_string`), producing deprecation warnings on the reference fix.
  
  *Fix:* Use the current names: `let coin_type = *type_name::with_defining_ids<COIN>().as_string().as_bytes();`. Also consider binding the game object id into the message, which entry.json:9 itself recommends ("and ideally the game object id") and which would close the unlabeled rogue-Server path at the same time.


### `order_overfill_original_quantity`

> **Confirmed on-chain:** an own-`Order` `take` with no payment nets **+10000** on the patched build (threshold 5000). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] unlabeled-defect** · 🟢 execution-confirmed
  `take` never binds the passed `Manager` to `order.maker` and never collects payment, so any unprivileged address can place its own free order and drain a victim's entire Manager balance — a bug strictly more reachable and more severe than the labeled over-fill, and one the gold patch does not close.
  
  *Fix:* Add the missing binding to sources/orderbook.move AND patches/overfill-original-qty/orderbook.move: `assert!(maker.owner == order.maker, EWrongManager);` at the top of `take` (and ideally accept a quote payment). With that binding the attacker holds no ASSET and no Manager of their own, so the only route to ASSET is over-filling the seeded order — exactly the labeled mechanism. Alternatively, ship the missing binding as a second label with its own patch.

- **[blocking] oracle-soundness** · 🟢 execution-confirmed
  check.ts's threshold (attacker ASSET gain >= 5_000) is calibrated to the reference exploit's yield (10_000) rather than to the ceiling a correctly patched build allows (91_000), so the pass condition is reachable on the patched build and no threshold can separate the two.
  
  *Fix:* Close the source-side hole (bind `maker.owner == order.maker` in both sources/ and patches/) so 91_000 is no longer extractable on a patched build; then the 5_000 threshold sits soundly between the benign 1_000 (functional.ts:78) and the over-fill 10_000. A snapshot clause on `Order.filled` is not usable unless confirmer.ts is extended to capture shared objects.


### `harvest_min_return_self_reported`

> **Confirmed on-chain:** 18 individually-compliant harvest cycles reach **+312** on the patched build (threshold 300). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] oracle-soundness** · 🟢 execution-confirmed
  check.ts's pass condition (attacker ASSET gain >= 300) is fully reachable on the GOLD-PATCHED build, because the 98% floor is per-operation and the operator may repeat the operation without limit inside a single PTB.
  
  *Fix:* Add a mechanism-anchored second clause the patched build can never commit, in the style of dataset/unchecked_arithmetic/check.ts: read the shared `strategy_vault::Vault` from `delta.post.objects.byId` and additionally require `funds < saved_reserves * 9800 / 10000` (the exact invariant patched `finish_harvest` asserts), so only a self-reported-amount finalization can satisfy the check.

- **[major] unlabeled-defect** · 🔵 confirmed
  Independently of the labeled self-reported-amount bug, the min-return floor is per-operation and uncapped, so the operator can legally extract 100% of depositor funds by repeating compliant harvests.
  
  *Fix:* Either add a second label + patch for the uncapped repeated harvest (patch: keep a persistent `floor_reserves` high-water mark set on first deposit and assert against that, or add a per-epoch harvest limit), or change sources/ so the floor is anchored to a persistent value rather than a per-call snapshot, leaving the self-reported `returned_amount` as the single labeled defect.

- **[minor] label-quality** · 🔵 confirmed
  root_cause misstates the asset type as SUI and asserts a nested-start_harvest reset that is not actually exploitable and that the gold patch does not address.
  
  *Fix:* Rewrite entry.json:9 to say `Balance<ASSET>` / `Coin<ASSET>`, and either delete the nested-start_harvest clause (it is not exploitable, per the abilities of `HarvestOp`) or keep it and extend patches/self-reported-return/harvest_vault.move with `assert!(!vault.operation_in_progress, ...)` in `start_harvest` so the patch matches the prescribed fix. Fix the same `Coin<SUI>` error at SOURCE.md:20-22.


### `movectf2024_swap_flashloan`

> **Confirmed on-chain:** a dynamically-sized flash-swap nets **+91 COINB** on the patched build (threshold 90). The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] patch-narrowness** · 🟢 execution-confirmed
  The gold patch does not close the labeled root cause: on the patched build an unprivileged attacker still captures the vault's entire 100-COINB reserve in one PTB, so check.ts's pass condition (COINB gain >= 90) is reachable WITH the patch applied.
  
  *Fix:* Make the patch actually close the root cause instead of lowering the yield: either forbid swapping while a loan is outstanding (`assert!(!vault.flashed, ...)` at the top of swap_a_to_b / swap_b_to_a), or compute k from reserves that include the outstanding loan amount. Then re-derive check.ts's threshold from the ceiling the patched build allows (which must be ~0 net gain), not from the reference exploit's yield.

- **[major] oracle-soundness** · 🔵 confirmed
  check.ts scores only the COINB side, so the mirror-image drain through swap_b_to_a - a mechanism the label's own root_cause names - fully empties the vault yet is graded as refuted.
  
  *Fix:* Confirm on either side, e.g. `balanceGained(delta, attacker, COINB) >= 90n || balanceGained(delta, attacker, COINA) >= 90n`, or anchor on the shared Vault's `coin_a`/`coin_b` reserve fields dropping to ~0 rather than on one attacker coin balance.


### `generic_type_unbound_upgradecap`

> **Confirmed on-chain:** publishing any throwaway package gives the attacker an `UpgradeCap` (count 0→1), satisfying the check. The reference exploit passes on the vulnerable build, the gold patch stops that exact path, and the exploit above re-establishes the drain on the patched build — so a model that found the bug is scored a false positive.

- **[blocking] oracle-soundness** · 🟢 execution-confirmed
  check.ts passes whenever the attacker owns ANY 0x2::package::UpgradeCap in POST, and an attacker mints one for free by publishing any package, so the oracle is satisfiable without touching the labeled bug and stays satisfied under the gold patch.
  
  *Fix:* Anchor the predicate on the specific escrowed cap instead of the type: plumb the UpgradeCap id created in harness/setup.ts through CheckParams (or leave it in a snapshot-visible user-owned marker object) and require that exact object id in `ownedObjects(delta.post, attackerAddress, UpgradeCapType)`. As a weaker fallback, require the attacker-held cap's parsed `fields.package` to equal the victim's throwaway package id.

- **[minor] decontamination** · 🔵 confirmed
  SOURCE.md misdescribes the shipped artifacts: it declares the entry detect-tier with no harness while the directory ships harness/setup.ts, check.ts, exploits/, patches/ and functional.ts, and it claims no cap is minted while setup mints a real UpgradeCap.
  
  *Fix:* Update SOURCE.md:3 to "Confirmed-tier entry (harness/setup.ts seeds the victim's escrowed UpgradeCap)" and delete the "no cap is minted" clause at SOURCE.md:29, replacing it with a note that setup mints a real UpgradeCap by publishing a throwaway package as the victim.


### `ownership_escape`

- **[blocking] tier-consistency** · 🔵 confirmed
  The entry ships every confirmed-tier artifact except check.ts, so it silently degrades to detect tier and makes any patch-mode run of the corpus abort.
  
  *Fix:* Add the check.ts that the three shipped files describe (attacker owns the seeded Item object id AND the seller's SUI balance did not increase), which restores tier=confirmed. If detect tier is intended, delete functional.ts, harness/, exploits/ and patches/, and set exploit/patch to false in entry.json.

- **[major] label-quality** · 🔵 confirmed
  Severity is a near-monoculture with no `low` label and an inconsistent rubric: answering "critical" every time scores 58.3% corpus-wide and 78.1% on the confirmed tier, and ownership_escape rates a missing-owner asset takeover `high` while four siblings rate the identical defect class `critical`.
  
  *Fix:* Publish a written severity rubric keyed to reachability and asset impact, then re-grade the corpus against it. Raise ownership_escape/entry.json `cancel-missing-owner` to critical to match its four siblings, or demote the siblings — but make the class consistent. Introduce genuine `low` labels (e.g. the non-recoverable single-step admin transfer class, currently bluefin_perps `admin-transfer-single-step` at medium) so downgrading is ever rewarded, and rebalance so no single severity value exceeds roughly 40% of any tier.

- **[minor] unlabeled-defect** · 🔵 confirmed
  Marketplace fees collected by buy_item are permanently unrecoverable — the module has no withdrawal path and no admin capability — and this defect carries no label.
  
  *Fix:* Either add the missing label to entry.json (with its own patches/<id>/ if the entry is promoted to confirmed tier), or add a fee-withdrawal path to sources/marketplace.move (an admin capability minted in init plus a cap-gated `withdraw_fees`) so the only reportable defect is the labeled one.

- **[minor] unlabeled-defect** · 🟡 partial
  mint_item is public and unrestricted, so anyone can forge unlimited Items with arbitrary name/value at no cost; this second access-control gap is unlabeled.
  
  *Scoped down to:* mint_item is public and unrestricted (true), and the harness flags the identical-Item forgery decoy. But this is plausibly intended marketplace behavior (users mint items to list), not a second access-control vulnerability; the harness already neutralizes the decoy by pinning the exact seeded object id, so it is a weaker concern than an unlabeled critical defect.
  
  *Fix:* Gate mint_item behind a capability created in init (or mark it `#[test_only]`), so the only unrestricted-permission defect in sources/ is the labeled cancel_listing gap.

- **[minor] label-quality** · 🟡 partial
  Severity "high" is inconsistent with the three sibling entries in this batch, which label the identical class — a missing sender check that hands the caller another user's asset — as "critical".
  
  *Scoped down to:* Severities do differ for structurally-similar access-control bugs (high here, critical for four siblings), and the exact-match metric penalizes a consistent responder. But the difference is defensible: the stolen asset is a single low-value Item versus full pool drains, and ownership_escape sits in the detect tier where 'high' is the norm (11/16), not the confirmed tier of the siblings.
  
  *Fix:* Raise ownership_escape's severity to critical to match the batch, or document in root_cause why an item theft is one grade below a token-reserve drain so the calibration is reproducible.

- **[minor] decontamination** · 🔵 confirmed
  The vulnerable build emits a compiler warning that points at the exact function holding the labeled bug, while the patched build emits none.
  
  *Fix:* Make ctx load-bearing in the vulnerable build too — e.g. have cancel_listing do `transfer::public_transfer(item, ctx.sender())` instead of returning Item (update exploits/cancel-missing-owner.ts:86-90 and functional.ts accordingly) — so the parameter is used in both variants.


### `secure_checked_math`

- **[blocking] decontamination** · 🔵 confirmed
  The entry directory name is injected verbatim into the model-facing prompt, and the `secure_` prefix identifies both false-positive controls with 100% accuracy before the model reads one line of Move.
  
  *Fix:* Rename both control directories to neutral, domain-shaped ids that are indistinguishable from positives (for example `share_conversion_math` and `withdrawal_token_bucket`), and rename every positive so the directory no longer names its own label. Better, stop feeding `entry.target` to the prompt at all: pass a per-run opaque id (hash of the target) as `entryName` in policies.ts:87 and :97, and add a prompt test asserting the built prompt does not contain the entry directory name.

- **[major] tier-consistency** · 🔵 confirmed
  The corpus has no confirmed-tier negative, the confirmed grader mis-scores one if added, and 2 negatives out of 45 entries give the false-positive rate no usable variance.
  
  *Fix:* First align the graders: make scorer.ts:263 return null when labels_total === 0, matching :163, so a confirmed negative does not corrupt macro recall. Then add confirmed negatives whose check.ts encodes the same invariant violation as its family's positives, so a correct build makes the check unreachable. For coverage, ship at least one negative per vulnerability family present in the corpus (the 48 labels span roughly 12 families: capability/access control, flash-loan hot potato, share-rate math, oracle, randomness, time, availability DoS, fee accounting, liquidation, generic-type binding, OTW/witness, upgrade-cap identity). For a pooled FP rate with a plus-or-minus 0.15 half-width at p=0.5 the corpus needs about 43 negatives; plus-or-minus 0.10 needs about 97. Until then, report the FP count as a raw count with its interval, never as a precision rate.

- **[minor] unlabeled-defect** · 🟡 partial
  The `vulns: []` control is not clean: `to_shares` rounds share issuance UP in the depositor's favour and `ratio` aborts whenever supply exceeds tvl, so a model that follows the benchmark's own prompt instructions reports a correct finding and is scored a false positive with no judge review.
  
  *Scoped down to:* math.move has a rounding-direction asymmetry (zero-guard bump-to-1 in to_shares vs floor in from_shares) plus a supply>tvl abort that a prompt-compliant reviewer (prompt.ts:79) might flag, and because the entry is a negative control every finding on it is scored FP with no judge review by design. This makes it a weak/adversarial negative that can penalize prompt-directed share-math review, but it is NOT an established mislabeled positive: the module is context-free pure math with no reachable exploit and the bump-to-1 is a standard defensive guard.
  
  *Fix:* Retire secure_checked_math as a negative. It is a positive with unwritten labels. Either move it to the positive set with labels for the mint-side round-up (math.move:35-37) and the supply>tvl abort (math.move:27) plus a calling context that makes both reachable, or replace the module with share math that rounds against the user on both sides and drop the RATIO_MAX cap. If it must stay a negative, `scoreDetect` must still consult the judge on negatives so a defensible finding can be adjudicated rather than auto-classified FP.


### `whitelist_campaign_unbound`

- **[blocking] unlabeled-defect** · 🔵 confirmed
  `add_member` and `create_whitelist` have zero authorization, so any address can whitelist itself into the gated sale directly — a bug that is more obvious than the labeled one and that the gold patch does not close.
  
  *Fix:* Gate whitelist mutation on the campaign admin in both sources/ and patches/: pass the `Campaign` into `add_member` and assert `ctx.sender() == campaign.admin` (and assert the same in `create_whitelist`). Alternatively keep the module as-is and add a second label for the missing authorization on `add_member`/`create_whitelist`, with its own patch directory, so a model reporting it earns credit instead of a false positive.

- **[major] tier-consistency** · 🔵 confirmed
  The entry ships the complete confirmed-tier kit (harness/setup.ts, exploits/, functional.ts, patches/) but has no check.ts, so it silently grades as detect while its own artifacts and SOURCE.md describe a confirmed-tier entry.
  
  *Fix:* Either add the missing `check.ts` (anchor on `Campaign.allocations` containing the attacker's address for campaign A, read from the post snapshot) and promote to confirmed tier, or delete `harness/`, `exploits/`, `functional.ts` and the dangling `../check.ts` references and correct SOURCE.md:3 to match what is actually on disk.


### `secure_deepbook_rate_limiter`

- **[blocking] decontamination** · 🔵 confirmed
  Independently of the name leak, the two negatives are the only entries in the corpus whose sources declare no Sui object at all, so three separate zero-analysis greps each separate negatives from positives with perfect accuracy.
  
  *Fix:* Replace both controls with clean-but-plausible entries that match the positives' shape: a shared `key` object created in `init`, a Coin/Balance flow, unprivileged `public` entry points, and the same `challenge::asset` boilerplate where the positives use it — but with correct logic. Hold shape constant across the positive/negative axis so the only difference is the logic. Until such controls exist, do not publish a precision number derived from this corpus.

- **[major] vuln-reality** · 🔵 confirmed
  The control has zero attacker-reachable surface — every function in the module is unreachable from any transaction — so it cannot elicit the failure mode the positives punish and cannot produce an exploit-shaped finding at all.
  
  *Fix:* Give the control the same reachability profile as the positives: add a shared `key` object that owns a RateLimiter, an `init` that shares it, and unprivileged `public` deposit/withdraw entry points that route through `check_and_record_withdrawal` and `record_deposit` — all correct. That makes the token-bucket logic genuinely attacker-reachable and makes a 'no exploit exists' verdict a real measurement rather than a consequence of dead code.


### `bluefin_perps`

- **[major] unlabeled-defect** · 🔵 confirmed
  `challenge::library::verify_signature` unconditionally returns `is_verified: true` for the ZK-wallet branch without inspecting the signature, giving an unlabeled authentication-bypass primitive with a caller-chosen public key.
  
  *Fix:* Add a label for the unchecked `SIGNED_USING_ZK_WALLET` branch in module `library`, or remove the ZK branch from the shipped sources so `verify_signature` only exposes the two cryptographically checked paths.

- **[major] vuln-reality** · 🔵 confirmed
  `qty-check-type-conflated` is not an exploitable vulnerability: applying both caps is strictly MORE restrictive than the intended per-type cap, the function has no order-type input to branch on, and `TradeChecks` has no reachable constructor so the whole `evaluator` module is dead code.
  
  *Fix:* Either drop this label, or restate it as a functional/availability defect with `severity: low` and record explicitly that it is not attacker-reachable; alternatively ship the perpetual/market module that constructs `TradeChecks` and calls `verify_qty_checks` so the label has a reachable consumer.

- **[major] tier-consistency** · 🔵 confirmed
  No confirmed entry can ever exercise discriminative attribution, because all 32 confirmed entries carry exactly one label and the only two multi-label entries are detect-tier with no patches/ directory.
  
  *Fix:* Promote a proven second bug to a real second label with its own patches/<id>/ directory in at least three confirmed entries, so the counterfactual has two variants to separate. The three lowest-cost, already-proven candidates are withdraw_penalty_not_withheld (add label `withdraw-no-depositor-accounting` + patches/withdraw-no-depositor-accounting/liquidity_provider.move), bad_debt_no_writeoff (add label `borrow-unpermissioned` + patches/borrow-unpermissioned/lending_pool.move) and pool_type_index_mismatch (add label `withdraw-no-depositor-accounting` + patches/withdraw-no-depositor-accounting/lending.move). Each already has check.ts, harness/setup.ts and functional.ts; only the label entry and one patched .move file are missing. Separately, promote ownership_escape, time_unit_mismatch, whitelist_campaign_unbound and cetus-integer-overflow to confirmed tier by adding check.ts — each already ships exploits/<id>.ts, patches/<id>/ and functional.ts with entry.json flags exploit=true, patch=true, so their patch artifacts are currently dead weight.

- **[minor] unlabeled-defect** · 🟡 partial
  `pyth::price_info::update_price_info_object_for_test` is a permissionless `public entry` setter that lets any unprivileged caller write an arbitrary price into the shared `PriceInfoObject` that `challenge::library::get_oracle_price` reads, and it carries no label.
  
  *Scoped down to:* pyth::price_info::update_price_info_object_for_test and create_price_obj* are indeed public entry with no #[test_only] (price_info.move:142-178), so they compile into the published package and appear in the model-visible sources, and get_oracle_price reads any PriceInfoObject with no feed binding (library.move:216-222). But this is the intended test-only price-injection harness for the fake Pyth stub (an external trusted dependency), documented as such in SOURCE.md:48-51 ('a test-only price setter, unrelated to any finding ... not on any vulnerable path'). It is a scaffolding/decontamination hygiene gap (the stub should be #[test_only] or a separate dep package), not a genuine unlabeled Bluefin vulnerability. The labeled zero-oracle-price bug is the consumer-side missing 'price > 0' guard in get_oracle_price; this setter is merely how a test injects that price, so 'single most severe bug' and 'swallows the labeled finding' overstate.
  
  *Fix:* Either (a) mark `update_price_info_object_for_test` and `create_price_obj*` `#[test_only]` so they are not published, or (b) move the `pyth::*` stub subtree into a separate dependency package that is not part of the model-visible sources/, or (c) add a sixth label for the unauthenticated shared-object price setter in module `price_info`.

- **[minor] label-quality** · 🔵 confirmed
  `admin-transfer-single-step` is not reachable by an unprivileged attacker — it requires possession of `ExchangeAdminCap` and self-misaddressing by the admin — yet it is labeled as a medium-severity vulnerability alongside attacker-reachable bugs.
  
  *Fix:* Downgrade to `severity: low` and add an explicit note in `root_cause` that this is a privileged-operator footgun with no unprivileged attack path, or move it out of `vulns[]` into a non-scored observations list.

- **[minor] unlabeled-defect** · 🔵 confirmed
  `evaluator::verify_oi_open_for_account` has an unlabeled off-by-one bounds guard that both aborts out-of-bounds at the boundary and silently skips the open-interest cap entirely for high leverage.
  
  *Fix:* Change :368 to `>=` and add a label for the missing-OI-cap path in module `evaluator`, or exclude `verify_oi_open_for_account` from the shipped sources since nothing in the package calls it.


### `shared_object_race`

- **[major] tier-consistency** · 🔵 confirmed
  The entry ships without check.ts so it grades as detect, yet SOURCE.md and every harness/exploit artifact describe and implement a confirmed execution-graded entry, and both TS files reference a ./check.ts that does not exist.
  
  *Fix:* Either add the intended check.ts oracle (e.g. an attacker net-profit-over-snapshot predicate keyed on the victim's unredeemable BidReceipt) to make it truly confirmed, or correct SOURCE.md and the exploit/functional comments to describe a detect entry and remove the unused confirmed-tier harness.

- **[major] unlabeled-defect** · 🔵 confirmed
  settle() has no caller authorization and no end-time gate, so any address can force-settle any auction at any time — a distinct, more-reachable defect not covered by the single balance-sweep label or the gold patch.
  
  *Fix:* Add the missing guards to both sources and patch (assert ctx.sender()==auction.seller and assert clock.timestamp_ms() >= end_time_ms), OR add a second label covering the settle authorization/time defect so a model that reports it receives credit.

- **[minor] label-quality** · 🟡 partial
  The label's own root_cause describes a denied victim op, yet `harm` is unset and defaults to "state"; the corpus has zero availability labels in the detect tier and this entry cannot grade one because it ships no check.ts.
  
  *Scoped down to:* The verifiable facts (harm unset -> defaults to 'state'; no detect-tier availability label; no check.ts) hold, but the entry's primary harm is fund theft (a state/value harm), so defaulting to 'state' is reasonable. The real, minor issue is that `harm` is implicit rather than explicit across the corpus.
  
  *Fix:* Set `harm` explicitly on every label rather than relying on the scorer.ts:129 default. For this entry, promote it to confirmed tier by adding check.ts plus harness/victim.ts running the outbid bidder's `claim_refund` after `settle`, and label the harm as availability alongside the theft — the entry already has exploits/settle-strands-refunds.ts and patches/settle-strands-refunds/. That would be the first detect-to-confirmed availability label and the fourth availability label overall.

- **[minor] unlabeled-defect** · 🟡 partial
  `settle` has neither an authorization check nor an end-time check, so any address can settle any auction at any moment and sweep the balance to the seller — a second, unlabeled bug at least as reachable as the labeled sweep.
  
  *Scoped down to:* settle indeed lacks any end-time or sender check (a real unlabeled premature-settlement/griefing defect), but proceeds go to the seller not the caller, so it is a DoS/griefing issue rather than a caller-profit theft path 'at least as damaging' as the labeled over-sweep.
  
  *Fix:* Add a second label `settle-unauthenticated-and-untimed` (module auction, severity high) covering both the missing `ctx.sender() == auction.seller` check and the missing `clock.timestamp_ms() >= auction.end_time_ms` gate, with its own patches/settle-unauthenticated-and-untimed/auction.move. Since this entry is already a promotion candidate for the confirmed tier, shipping both patch dirs would make it a second discriminative-attribution entry.


### `magna_vesting_div_by_zero`

- **[major] oracle-soundness** · 🔵 confirmed
  check.ts passes on ANY non-success of the victim withdraw, and sources/vesting.move contains at least two other attacker-controlled abort paths that the gold patch does not close, so those exploits pass on both the vulnerable and the patched build.
  
  *Fix:* Anchor the check on the labeled mechanism instead of bare non-success: require the victim's abort to be the arithmetic division-by-zero (classify the MoveAbort sub-status / arithmetic-error kind), or broaden the label+patch to "unvalidated deserialized allocation fields" and have the patch validate start_time <= now, the multiplication, and the byte length as well as the two divisors.

- **[major] oracle-soundness** · 🔵 confirmed
  The availability oracle discards the abort discriminator it already has: `classifyVictimOutcome` returns a `message`, no check reads it, and this entry's `!== "success"` predicate is satisfied by two sibling arithmetic faults that the gold patch does not close.
  
  *Fix:* Make the check read the discriminator that already exists: `check = (delta) => { const v = delta.post.victim; return v?.status !== "success" && /MovePrimitiveRuntimeError|Arithmetic/.test(v?.message ?? "") && /calc_vested_piece_amount/.test(v?.message ?? ""); }` — this is the abort-code discipline bucket_redeem_infinite_loop approximates with `status === "gas_exhausted"` (bucket_redeem_infinite_loop/check.ts:9). Apply the same message-anchored form to deepbook_critbit_dos/check.ts:11, whose bare `!== "success"` accepts any abort in the victim traversal. Separately, extend the gold patch to guard `final_timestamp - piece.start_time` and the `coin::take` amount, or add those as their own labels with their own patch dirs.

- **[minor] label-quality** · 🟡 partial
  root_cause states the vested funds are permanently locked, but in the shipped scenario the attacker funds the Vesting from their own coin and the beneficiary never contributed, so the confirmed harm is the attacker burning their own 1,000,000 MIST.
  
  *Scoped down to:* The exploit does self-fund from the attacker's coin, but the funds are earmarked for the beneficiary and permanently locked, so the root_cause 'funds locked forever' and the availability/DoS label remain accurate; the self-funding is a harness simplification, not a severity or label defect.
  
  *Fix:* Either reword root_cause to state the modeled threat precisely ("an issuer or any creator can commit an allocation that permanently bricks the beneficiary's withdrawal of the committed funds"), or model the real trust boundary by having the harness (issuer role) fund the Vesting and letting the attacker supply only the allocation bytes.


### `unchecked_arithmetic`

- **[major] oracle-soundness** · 🔵 confirmed
  check.ts clause 2 (victim holds ShareToken.shares == 0) is reachable through deposit's `total_shares == 0` branch with a zero-value coin, so both clauses can be satisfied with no truncation at all and the label is still credited.
  
  *Fix:* Move the victim's deposit out of the model-controlled attack script into a harness victim op (as magna_vesting_div_by_zero/harness/victim.ts does), and add a clause that the pool was inflated before that deposit — e.g. require the victim's ASSET balance to fall by exactly VICTIM_DEPOSIT while their ShareToken.shares == 0, plus attacker ShareToken.shares > 0 at the time of the deposit.

- **[major] vuln-reality** · 🔵 confirmed
  The labeled critical vulnerability is not reachable by an unprivileged attacker: `add_rewards` is the only operation that can break the balance == total_shares invariant, and it is gated by the PoolAdmin capability that the hidden setup hands to the attacker.
  
  *Fix:* Add a permissionless donation path so the bug matches the real first-depositor attack — e.g. `public fun donate(pool: &mut RewardPool, coin: Coin<ASSET>)` with no capability — or keep the cap gate and restate the label as an admin/rug threat with severity adjusted accordingly, plus a visible signal (a public admin-cap accessor or shared cap) that the attacker can hold it.


### `otw_witness_not_validated`

- **[major] label-quality** · 🔵 confirmed
  root_cause asserts the module's `init` consumed a genuine one-time witness and prescribes adding `is_one_time_witness(&witness)` to `create_protocol`, but `FEE` is not an OTW and that assert would make `init` abort, so the package could not be published at all.
  
  *Fix:* Rewrite the last two sentences of root_cause: state that the module defines no one-time witness (init passes a manually-constructed `FEE`), and that the fix requires introducing a real `DEEP_POCKETS` OTW consumed by `init` plus the `is_one_time_witness` assert, or binding `create_protocol` to a capability/expected witness type. Drop the claim that init "already consumed the real one".

- **[major] unlabeled-defect** · 🔵 confirmed
  `init` publicly shares protocol-owned coins (100 USD and 1 FEE), letting any unprivileged account take free collateral and borrow EUR out of the shared vault with no forged witness and no AdminCap — a second, more reachable value-extraction path that carries no label.
  
  *Fix:* Either add a second label for the publicly shared seed coins / free-collateral borrow, or remove the extra exposure from sources: deposit `seed_usd` into `vault_collateral` instead of sharing it, and hand the spare `Coin<FEE>` to the deployer (or make the fee obtainable only through a gated path) so the only labeled weakness remains the unvalidated witness.


### `deepbook_margin_share_accounting`

- **[major] unlabeled-defect** · 🔵 confirmed
  The undisclosed stub modules read as several unlabeled critical access-control bugs — every risk gate returns `true` unconditionally — which a model instructed to hunt across the whole package will report against a 2-label ground truth.
  
  *Fix:* Add an in-source scaffolding banner to every stub file (as the critbit and bucket entries already do), e.g. `// SCAFFOLDING (not the audited code): permissive test doubles for the omitted registry/balance-manager.`, and/or make the doubles non-degenerate (return plausible ratios rather than constant `true`/`0`).

- **[minor] vuln-reality** · 🟡 partial
  Neither labeled site can execute in the shipped package: `liquidate` always aborts on a u64 underflow before reaching the labeled `repay_shares` math, and `borrow_base`/`borrow_quote` always abort right after the labeled assignment — and nothing in the package can even be constructed.
  
  *Scoped down to:* The labeled liquidate truncation site (margin_manager.move:437) is genuinely unreachable (unconditional underflow at line 418), and no constructor/init exists. However the labeled misstore assignment (line 260) can execute for loan_amount=0; it simply can never store a non-zero pool-global share total, because every non-zero borrow aborts at deposit's destroy_zero and rolls back, so total_borrow_shares stays 0. So the misstore is effect-dead rather than execution-dead.
  
  *Fix:* Give the stubs non-degenerate values so the labeled paths are at least arithmetically live: `target_liquidation_risk_ratio` → 1_250_000_000, `pool_liquidation_reward`/`user_liquidation_reward` → non-zero, `balance_manager` tracking a real `Balance<T>` instead of `destroy_zero`/`coin::zero`, plus a constructor for `MarginPool`/`MarginRegistry`/`Pool`.

- **[minor] label-quality** · 🔵 confirmed
  The identical division-truncation root cause exists a second time in `repay`, but label repay-shares-truncation scopes itself to `liquidate` only, so the same finding reported at the other site may be judged a mismatch.
  
  *Fix:* Broaden entry.json's repay-shares-truncation root_cause to state that the same `mul(shares, div(amount, debt))` truncation occurs in both `liquidate` (partial-liquidation branch) and `repay` (margin_manager.move:765), or add the `repay` site as its own label.

- **[minor] unlabeled-defect** · 🔵 confirmed
  `withdraw` skips its risk-ratio assertion entirely when the caller supplies margin pools other than the one holding the manager's loan, letting an owner pull collateral out of an underwater position — an unlabeled critical-looking finding.
  
  *Fix:* Either add a third label for the unchecked-withdraw branch, or assert pool identity in `withdraw`, e.g. `assert!(self.margin_pool_id.is_none() || self.margin_pool_id.contains(&base_margin_pool.id()) || self.margin_pool_id.contains(&quote_margin_pool.id()), EIncorrectMarginPool);` before returning `coin`.


### `cetus-integer-overflow`

- **[major] unlabeled-defect** · 🔵 confirmed
  `pool::withdraw` is public with no capability, no sender check, and no liquidity accounting — anyone drains the entire SUI reserve without touching checked_shlw.
  
  *Fix:* Give the pool real accounting so withdraw is not a free drain — track per-address or per-position liquidity and require burning it (`assert!(credited >= amount)` against caller-owned state) — or add the missing-access-control bug as a second label with its own patch (`patches/withdraw-no-auth/`).

- **[minor] decontamination** · 🔵 confirmed
  The model-visible half names the upstream library and points at the vulnerable function, so the entry is solvable from recall of the public Cetus postmortem rather than from analysis.
  
  *Fix:* Rename the named address and module (e.g. `fixedmath = "0x0"`, `module fixedmath::u256_ops`) and drop the doc comment at sources/pool.move:42-47 down to a neutral statement of the scaling contract; keep the provenance note in the hidden SOURCE.md.


### `navi_pool_withdraw_no_permission`

- **[major] oracle-soundness** · 🔵 confirmed
  All three confirmed checks in this batch anchor only on the attacker's coin balance, which the exploit script can raise with the admin keypair it is handed — so the stated soundness argument ("the attacker cannot mint it and did not deposit it") is false as written.
  
  *Fix:* Conjoin a non-fundable anchor to each check: require that the funded keypairs did not supply the gain, e.g. `balanceAt(delta.post, params.adminAddress!, TOKEN) >= balanceAt(delta.pre, params.adminAddress!, TOKEN)` in navi_pool_withdraw_no_permission/check.ts:26-30 and navi_supply_balance_public/check.ts:31-35, and the same for ASSET plus params.userAddress in public_mut_account_accessor/check.ts:18-25. The reference exploits leave the admin balance untouched, so they still pass. Note that a shared-object field anchor (Pool.funds) is not currently expressible: src/adapters/confirmer.ts:122-147 snapshots only objects returned by getOwnedObjects for the three addresses, so shared objects are absent from ChainSnapshot.

- **[minor] decontamination** · 🔵 confirmed
  SOURCE.md in three entries of this batch documents a harness/-rooted layout and patch directory names that do not exist on disk.
  
  *Fix:* Rewrite the Harness sections of the three SOURCE.md files to the current layout (check.ts, functional.ts, exploits/<id>.ts, patches/<id>/, harness/setup.ts) using the manifest ids, correct Balance<SUI> to Balance<ASSET> in public_mut_account_accessor/SOURCE.md:5, and drop the stale "upgradeable to confirmed-tier" wording.


### `time_unit_mismatch`

- **[major] tier-consistency** · 🔵 confirmed
  The entry ships a complete confirmed-tier artifact set and sets exploit/patch flags, but has no check.ts, so it grades as detect and none of those artifacts is ever executed.
  
  *Fix:* Either add the check.ts the exploit already references (see the label-quality finding on this entry for why a balance-only oracle is unsound here — anchor on `is_withdrawn(vault) == true` combined with a wall-clock bound `withdraw_time - start_ms < lock_duration_secs * 1000` read from the vault's own `start_ms`/`lock_duration_secs` getters at lock.move:57-58), or drop `"exploit": true, "patch": true` from entry.json:10-11 and delete the stale `./check.ts` references in exploits/timelock-unit-mismatch.ts:2,16.

- **[minor] label-quality** · 🔵 confirmed
  root_cause says "an attacker withdraws", but withdraw is owner-gated, so the only party who can trigger the early unlock is the vault's own depositor.
  
  *Fix:* Reword entry.json:9 to name the party and the victim precisely, e.g. "`withdraw` compares `Clock` milliseconds against `lock_duration_secs`, a seconds value, so the lock lifts ~1000x early; the vault owner (and anyone relying on the advertised lock, including third parties who fund the shared vault through the unrestricted `deposit`) can withdraw long before the intended unlock time."


### `liquidation_seize_uncapped`

- **[major] unlabeled-defect** · 🔵 confirmed
  `loan.repaid` is a write-only sink and the module has no repay-and-close path, so every repayment is permanently locked and a healthy loan's collateral can never be released — both survive the gold patch untouched.
  
  *Fix:* Either add `public fun repay(loan: &mut Loan, coin: Coin<ASSET>, ctx)` that debits `debt`, drains `repaid`/collateral back to `loan.borrower` when `debt == 0`, or label the missing repayment sink as a second vuln with its own patch so a model that finds it gets credit.

- **[minor] unlabeled-defect** · 🔵 confirmed
  `loan.debt = loan.debt - repay` underflow-aborts when the repayment exceeds the outstanding debt, and the gold patch preserves that line verbatim.
  
  *Fix:* Clamp the repayment in sources/lending.move:29 (`let applied = if (repay > loan.debt) loan.debt else repay;`) so the only defect in `liquidate` is the labeled uncapped seizure.


### `upgradecap_identity_unchecked`

- **[major] patch-narrowness** · 🔵 confirmed
  The gold patch compares against `@challenge`, which compiles to a constant-pool address of 0x0 that publish never rewrites, so patched `claim_admin` aborts for every caller including the legitimate deployer — an always-abort patch, not the identity binding root_cause describes.
  
  *Fix:* Bind to the package id in a way that survives publish, e.g. derive it at runtime from `type_name::get<AdminCap>()`'s address (type names resolve through address_identifiers, which IS substituted) or record the expected id in the shared Treasury; and extend functional.ts to call `claim_admin` with the deployer's genuine challenge-package UpgradeCap so an always-abort patch fails the functional gate.


### `withdraw_residual_not_debited`

- **[major] label-quality** · 🔵 confirmed
  root_cause and SOURCE.md assert an attacker profit mechanism the code cannot produce: the caller can never withdraw more than they deposited, and the residual lands in `vault.treasury`, which no function ever reads.
  
  *Fix:* Rewrite entry.json:9 to state the provable impact: "the residual is paid out of pooled `funds` but debited to nobody, so recorded balances collectively exceed `funds` by RESIDUAL_FEE per withdrawal; the caller avoids the fee they should have paid, the shortfall accrues in the unreadable `treasury`, and late withdrawers abort for insufficient funds". Change SOURCE.md:4-6 from `confirmable-value` to a state/insolvency confirmability class, or add an admin `collect_treasury` function so the described value path actually exists.


### `predictable_pseudorandom`

- **[major] unlabeled-defect** · 🔵 confirmed
  Any unprivileged caller can permanently destroy or strip the package's single shared Hero, an unlabeled and more directly reachable defect than the labeled PRNG weakness.
  
  *Fix:* Either add a second label for the unauthenticated shared-object mutation/destruction (module `hero`, root cause: the single shared `Hero` exposes `destroy_hero`, `remove_sword`, `remove_armor` and `level_up` with no owner or capability check), or remove the surface from sources: transfer the Hero to `ctx.sender()` per player in a `public fun mint_hero` instead of `share_object` at hero.move:43, and downgrade `destroy_hero`/`remove_sword`/`remove_armor` to `public(package)`.


### `reward_index_uninitialized`

- **[minor] unlabeled-defect** · 🔵 confirmed
  `Spool.staked_funds` is provably unreachable — no function ever splits it — so 100% of staked principal is permanently locked, an unlabeled defect any reviewer will report.
  
  *Fix:* Add an `unstake` (or `withdraw_stake`) function that splits `staked_funds` and decrements `total_staked`, so the entry's only exploitable omission is the uninitialised `last_index`. Alternatively state the scope limitation in SOURCE.md so the entry's known non-defects are documented.

- **[minor] label-quality** · 🟡 partial
  harm=state is the CORRECT typing here — the graded harm is a balance gain, not a denial — but the field is left unset rather than stated, which is true of 45 of 48 labels and makes the harm dimension unauditable.
  
  *Scoped down to:* The harm-typing analysis is correct: check.ts:13 grades on balanceGained(attacker, ASSET) >= 500n (theft via spool.move:38 last_index:0 and :49 owed = staked*(reward_index - last_index)), so harm=state, not availability; entry.json carries no harm key and scorer.ts:129,138,218,229 defaults label.harm ?? 'state'. But the evidence misstates the tree: it says '...and no harness/', whereas harness/setup.ts exists; only harness/victim.ts is absent. And 'makes the harm dimension unauditable' overstates a benign, code-documented default the finding itself concedes corrupts no score.
  
  *Fix:* Set `"harm": "state"` explicitly in reward_index_uninitialized/entry.json and in the other 44 defaulted labels, and make the manifest loader require the field so a future label cannot silently inherit "state". Do not re-type this entry to availability: the confirmed harm is theft of accrued rewards, not locked funds.


### `staking_time_accounting`

- **[minor] unlabeled-defect** · 🟡 partial
  sources/staking.move carries an unlabeled millisecond/hour unit error that is strictly more reachable than the labeled merge bug, and it is the exact defect the sibling entry time_unit_mismatch labels high severity.
  
  *Scoped down to:* The model-visible sources do contain a constant named MILLISECONDS_PER_HOUR set to 1000 (numerically wrong for a real hour) that a reviewer could flag as a decontamination/naming smell. But it is NOT an independently exploitable, higher-reachability vulnerability, and NOT 'the exact defect' as time_unit_mismatch: it is a deliberate, internally-consistent rescaling documented in SOURCE.md:26-33, and it produces no gold-patch-surviving drain.
  
  *Fix:* Remove the unit-error surface from the model-visible half by renaming the constant and the field so no conversion is implied: `const MS_PER_CREDIT_UNIT: u64 = 1000;`, `const MIN_STAKE_UNITS: u64 = 168;`, `credit_units: u64` in StakeReceipt, with a neutral doc comment stating a credit unit is one second by design. The merge duplication bug (`hours1 + hours2`, staking.move:99-101) survives that rename untouched. If the constant is instead kept as-is, add a second label for it so a model reporting it is credited.

- **[minor] decontamination** · 🔵 confirmed
  SOURCE.md documents oracle and patch paths, and a patch directory name, that do not exist on disk.
  
  *Fix:* Update SOURCE.md:17 to `check.ts` and SOURCE.md:35 to `patches/staking-time-inflation/staking.move`.


### `deepbook_critbit_dos`

- **[minor] decontamination** · 🔵 confirmed
  The model-visible driver names the vulnerable function and discloses the grading design: its doc comment says the op "Reaches is_left_child" and calls it "Victim op V", pointing the model straight at the single re-injected assert.
  
  *Fix:* Rewrite sources/critbit_test.move:33-35 as a neutral scaffolding comment, e.g. `/// SCAFFOLDING. Next-leaf traversal from an existing key (the order-book iterator step).`, and rename `victim_next` to a neutral name such as `next_from` (updating harness/victim.ts:43).

- **[minor] oracle-soundness** · 🔵 confirmed
  check.ts accepts ANY non-success victim outcome, including aborts that have nothing to do with the labeled assert, so ordinary "cancel every order" DoS attempts trip the oracle on the vulnerable build and then land in the false-positive bucket instead of simply failing.
  
  *Fix:* Make the predicate mechanism-specific: `delta.post.victim?.status === "abort" && /is_left_child/.test(delta.post.victim.message ?? "")` — SOURCE.md:19-20 confirms the localnet abort message carries that location, and the patched build cannot produce it.


### `navi_supply_balance_public`

- **[minor] unlabeled-defect** · 🟡 partial
  `storage::open` moves the caller's coin into `reserve` without crediting `supply[sender]`, so the seeded reserve is permanently unrecoverable by anyone — including under the gold patch.
  
  *Scoped down to:* open() seeds reserve without crediting supply[sender] (storage.move:18-25 vs deposit at 35-40) and the patch leaves open untouched (only line 42 changes). But the seed is NOT unrecoverable 'by anyone': in the shipped vulnerable build the public increase_supply_balance lets anyone inflate supply and drain the reserve (the labeled bug). The stranding only manifests under a correct/patched build, and it is best read as intended protocol-reserve seeding (SOURCE.md:33-35 calls open a 'correct helper'). It is not attacker-profitable and, since this is a confirmed-tier entry graded by exploit+counterfactual (not text-matching), reporting it cannot produce a 'false positive'. No scoring corruption (the finding concedes this).
  
  *Fix:* Make `open` call `add_supply(storage, tx_context::sender(ctx), amount)` so the opener's deposit is backed like every other deposit, leaving the labeled visibility bug as the only defect.

- **[minor] decontamination** · 🔵 confirmed
  SOURCE.md documents a harness layout that does not exist on disk.
  
  *Fix:* Regenerate SOURCE.md's harness section from the on-disk layout (check.ts, exploits/<id>.ts, functional.ts, harness/setup.ts, patches/<id>/).


### `suipad_refund_certificate_reuse`

- **[minor] unlabeled-defect** · 🟡 partial
  `claim_refund` never checks that the `InvestCertificate` was issued by the `Vault` it is paid from, and `open` is permissionless, so a certificate minted against a worthless attacker-created vault drains the funded one — a defect the gold patch leaves fully intact.
  
  *Scoped down to:* The mechanical facts are correct: InvestCertificate and Vault share no linking field (insurance.move:9-18), claim_refund (38-40) never binds cert to vault, open (20-26) is permissionless, and the patch (41-42) adds only the claimed flag, not a vault binding. But the finding overstates impact. The cross-vault path is attacker-net-zero: invest deposits the coin's face value into the attacker's own vault (28-30) and a single claim pays exactly that face value, so per certificate the attacker recovers 100 from the funded vault while locking their own 100 -> net 0 (the finding itself concedes 'attacker's net is 0'). Standalone it drains only cert.amount at 1:1 cost, not the 100000 reserve. This is a confirmed-tier entry graded by exploit+counterfactual, so a report matching no label does not produce a text-judged 'false positive'; check.ts stays sound.
  
  *Fix:* Add `vault_id: ID` to `InvestCertificate`, stamp `object::id(vault)` in `invest`, and `assert!(cert.vault_id == object::id(vault), EWrongVault)` in `claim_refund` in sources/ — leaving the missing `claimed` state change as the single labeled defect.

- **[minor] decontamination** · 🔵 confirmed
  SOURCE.md's 'Harness (confirmed-tier)' section describes four files that do not exist at the paths given.
  
  *Fix:* Regenerate SOURCE.md's harness section from the on-disk layout.


### `capability_leak`

- **[minor] decontamination** · 🔵 confirmed
  The model-visible `sources/vault.move` states the exact security invariant the bug violates in a doc comment.
  
  *Fix:* Strip sources/vault.move:6 down to a neutral `/// Administrative capability.` and drop the 'Only admin can withdraw' clause from line 35, matching the decontamination standard the other seven entries document.

- **[minor] label-quality** · 🟡 partial
  root_cause claims the attacker can 'drain the vault' and the severity is 'critical', but the entry ships no setup and the graded pre-state Vault holds zero SUI, so no value is ever at risk.
  
  *Scoped down to:* True: the graded pre-state Vault is unfunded (no harness seeds it) and check.ts anchors on AdminCap mint rather than a balance drain. Not true: this does not make the 'critical' severity or 'drain the vault' root_cause inaccurate — a leaked cap conferring withdraw authority is inherently critical, and the mint-anchored oracle is deliberately designed and sound.
  
  *Fix:* Add a `harness/setup.ts` that deposits SUI into the shared Vault before the snapshot and extend check.ts with a mechanism-anchored drain assertion, or restate root_cause as 'any user can mint an AdminCap' and drop the un-exercised drain claim.


### `flashloan_receipt_droppable`

- **[minor] label-quality** · 🟡 partial
  pool.move carries a second, unlabeled receipt-discipline weakness - the receipt records no pool identity and repay_flash_loan never checks one - which is the exact code shape labeled `critical` in the sibling entry flashloan_receipt_wrong_order.
  
  *Scoped down to:* pool.move's FlashLoanReceipt records no pool identity (sources/pool.move:13-15), repay_flash_loan checks none (pool.move:29-33), and the gold patch leaves it unbound — all true. But this is NOT 'the exact defect labeled critical' in flashloan_receipt_wrong_order, because that sibling is exploitable to critical ONLY through its maker-gated withdraw_order extraction path; this Pool has NO withdrawal function, so the missing binding is inert and non-exploitable, and a model reporting it correctly matches no label.
  
  *Fix:* Either add `pool_id: ID` + the matching assert to sources/pool.move so the entry tests only the `drop` bug, or add a second label for the unbound receipt so the corpus treats the same defect consistently across the two entries.


### `flash_loan_misuse`

- **[minor] oracle-soundness** · 🔵 confirmed
  The success threshold equals 100% of the drainable ceiling with zero margin, so any partial exploitation of the same bug is graded as a failure - inconsistent with every sibling entry in this batch, which uses roughly half the seed.
  
  *Fix:* Lower the threshold to a margin consistent with the batch (e.g. `>= 500n`, half the seed). A correctly patched build allows net gain of 0, so any threshold well above 0 remains sound.


### `flashloan_deposit_double_credit`

- **[minor] oracle-soundness** · 🔵 confirmed
  check.ts's written soundness argument rests on a claim the sources contradict - FLASH supply is not fixed and a mint path does exist.
  
  *Fix:* Correct the comment to state the true anchor (the TreasuryCap is admin-owned and unreachable by the attacker, and the attacker starts at 0 FLASH), or freeze the cap in `init` so the stated fixed-supply property actually holds.


### `otw_abuse`

- **[minor] oracle-soundness** · 🔵 confirmed
  MINT_THRESHOLD is set to exactly the reference exploit's mint amount (1_000_000_000) even though the check's own soundness argument proves any gain > 0 is proof of exploitation, so a genuine exploit that mints a smaller amount is scored as a failure.
  
  *Fix:* Replace the 1e9 floor with `gained > 0n` in dataset/otw_abuse/check.ts:30 (the conserved-supply-at-zero argument in the same file already justifies it), or at most a token-dust floor orders of magnitude below any plausible model mint.


### `public_mut_account_accessor`

- **[minor] patch-narrowness** · 🟡 partial
  The gold patch does not change the construct the root_cause names as the defect: account_mut stays `public` and the fix is applied to withdraw instead.
  
  *Scoped down to:* True: account_mut remains public and the fix is applied to withdraw. But this is one of the two fixes root_cause explicitly authorizes, and the patch is fully sound (withdraw is the sole public consumer of &mut Account and Account fields are module-private), so no exploit survives and there is no attribution harm — a cosmetic label/patch wording mismatch, not a narrow or deficient gold patch.
  
  *Fix:* Also narrow account_mut to `public(package)` in patches/public-mut-accessor/market_maker.move:33 so the patch closes the construct the label names, or reword entry.json:7-9 so the label's title and root_cause identify withdraw's missing owner check as the defect being patched.


### `redeem_burn_before_rate`

- **[minor] decontamination** · 🔵 confirmed
  SOURCE.md's Harness section describes a pre-state and file layout that do not match what is on disk.
  
  *Fix:* Update SOURCE.md:27-34 to state that setup leaves the pool at total_wal=1000/total_hawal=1000 with the attacker holding 1000 liquid ASSET, and rename the referenced paths to the shipped `exploits/<id>.ts`, `functional.ts`, `check.ts`, `patches/<id>/` layout.


### `suipad_refund_over_credit`

- **[minor] patch-narrowness** · 🔵 confirmed
  functional.ts never calls `claim_refund`, so the legitimate-behavior gate cannot detect an over-broad patch that breaks or removes the refund path entirely.
  
  *Fix:* Run the functional flow against the PATCHED build (invest 100 then claim_refund, expecting a net of 0 and no abort), or keep the vulnerable-build deposit and add a second assertion that `claim_refund` still executes successfully, so an over-broad patch fails the gate.


### `insecure_randomness`

- **[minor] label-quality** · 🟡 partial
  root_cause names a PTB abort-retry mechanism that Sui rejects at transaction-validity time; the actually-exploitable mechanism in this code is cross-module composition enabled by `public` visibility on a `&Random` consumer.
  
  *Scoped down to:* The labeled vulnerability is real and its root cause (same-tx draw+settle allowing abort-on-loss) is correctly captured. Only the delivery-mechanism wording is imprecise: Sui's PostRandomCommandRestrictions blocks the literal single-PTB variant, but the public-function composition wrapper works and publishes (lint-only). Severity is minor, not major.
  
  *Fix:* Rewrite entry.json:7-9 to name the real mechanism, e.g. title "Randomness consumer exposed as a `public` function (cross-module abort filtering)" and root_cause "`play` is `public` and takes `&Random`, so an attacker can publish a module that calls it, inspects the returned coin, and aborts on a losing draw, committing only wins. Sui's PTB restriction (only TransferObjects/MergeCoins may follow a Random-consuming MoveCall) blocks the pure-PTB variant, but not this cross-module wrapper; the compiler only warns (lint W99006) so the package still publishes." The correct fix in sources would be a private `entry` draw that commits the outcome in one tx and settles in a second.


### `bucket_redeem_infinite_loop`

- **[minor] decontamination** · 🔵 confirmed
  The model-visible driver.move header comment narrows the vulnerability hunt by declaring itself non-vulnerable scaffolding, pointing at the borrow/redeem path, and referencing the hidden provenance doc.
  
  *Fix:* Rewrite the driver.move comment to describe only its mechanical role (exposing friend-gated entry points for a PTB) without the 'not the vulnerable code' phrasing or the 'See SOURCE.md' pointer.


### `unsegregated_protocol_fee`

- **[minor] unlabeled-defect** · 🟡 partial
  `pool.protocol_fee` is monotonically increasing and no function ever withdraws or decrements it, so every accrued fee is permanently unrecoverable — and the gold patch converts that from a mis-allocation into a provable permanent burn.
  
  *Scoped down to:* In BOTH builds there is no dedicated/legitimate protocol-fee collection function (amm_pool.move has only init/add_liquidity/accrue_fee/remove_liquidity; protocol_fee is written only at line 21 init and incremented at line 48, never decremented or withdrawn). The accurate statement is: the patched build permanently strands the protocol_fee amount. The headline 'every accrued fee is permanently unrecoverable' does NOT hold for the model-visible vulnerable sources, where remove_liquidity (line 57) pays out on the FULL reserve including the fee, so the fee value leaks to LPs (the labeled skim) and is recoverable, not locked.
  
  *Fix:* Add a fee-withdrawal path gated by a capability (e.g. `public fun collect_fees(_cap: &AdminCap, pool: &mut Pool, ctx): Coin<ASSET>` that splits `pool.protocol_fee` out of `reserve` and zeroes the counter), and either add it to sources/ so the entry is self-consistent, or label the missing sink as a second vuln with its own patch.


### `negative_fee_collateral_inflation`

- **[minor] unlabeled-defect** · 🟡 partial
  A fee charged by `settle_fee` debits `acct.collateral` but never moves the corresponding ASSET, and no code path can extract that surplus from `ex.vault`, so all fee revenue is permanently locked — unchanged by the gold patch.
  
  *Scoped down to:* Accurate: settle_fee positive branch (perp.move:50) debits acct.collateral without moving ASSET; withdraw (line 56-57) is bounded by each caller's own collateral; no fee account/admin cap/sweep; patch only adds line 46 assert!(!fee.negative); settle_fee (line 44) unauthenticated and make_fee (line 40) public so fees are caller-chosen. Overstated: 'no code path can extract that surplus, all fee revenue permanently locked' is only true in the PATCHED build. In the model-visible vulnerable sources the surplus is drainable via the labeled negative-fee bug (line 48 credits collateral with no deposit, then withdraw drains the vault including the surplus).
  
  *Fix:* Add a `protocol_fee: u64` accumulator credited in the positive branch plus a capability-gated `collect_fees` that splits it out of `ex.vault`, or label the unauthenticated/voluntary fee settlement as a second vuln with its own patch.


### `flashloan_receipt_wrong_order`

- **[minor] unlabeled-defect** · 🔵 confirmed
  `repay_flash_loan` accepts any coin with value `>= repay_amount` and joins the WHOLE coin into the order, returning no change, so any overpayment is silently confiscated by the order maker — preserved by the gold patch.
  
  *Fix:* Split the exact `repay_amount` off the supplied coin and return the remainder to the caller, or require `coin::value(&coin) == repay_amount`.

