# Attack Vectors Reference — Shared Objects, PTBs & Concurrency (2/4)

> Part 2 of 5 · Vectors 31–60 of 143 total
> Covers: shared object races, programmable transaction blocks, flash loans, hot potato pattern, MEV, DoS, upgrade security, clock/time

---

**31. Shared Object Race Condition — Missing Version/Sequence Check**

- **D:** Shared object mutated by concurrent transactions without a version or sequence number check. Parallel transactions can interleave, causing inconsistent state (e.g., double-counting, lost updates in a liquidity pool).
- **FP:** `version` field checked and incremented atomically on every mutation. Mysticeti consensus ordering prevents races for this specific pattern. Single-writer pattern enforced.

**32. Shared Object DoS via Transaction Spam**

- **D:** Attacker spams transactions targeting a shared object, filling the consensus ordering queue. Legitimate transactions (liquidations, time-sensitive operations) are delayed or fail due to contention.
- **FP:** Rate limiting on shared object access. Alternative paths that don't require the contested shared object. Operations designed to be idempotent and retryable.

**33. Shared Object Used Where Owned Would Suffice**

- **D:** Object shared unnecessarily when owned-object + transfer would work. Shared objects require consensus ordering (slower, more expensive), and expose the object to contention and DoS vectors.
- **FP:** Shared object genuinely required (multi-user access: pools, DEXs, marketplaces). Documentation justifies shared status. Performance implications acceptable.

**34. PTB Flash Loan — Missing Hot Potato Pattern**

- **D:** Lending protocol allows borrow and repay as separate transactions (or within a PTB without enforcement). Borrower takes a loan, manipulates state within the PTB, and repays — or never repays at all.
- **FP:** Hot potato pattern: borrow returns a `FlashLoanReceipt` struct with no `drop` or `store` abilities, which must be consumed by the repay function within the same transaction. Compiler enforces this.

**35. Hot Potato Has drop or store Ability**

- **D:** Flash loan receipt or obligation struct incorrectly given `drop` or `store` ability. With `drop`, the borrower discards the receipt without repaying. With `store`, the receipt can be stored and repaid later (or never).
- **FP:** Receipt struct has no abilities (no `copy`, `drop`, `store`, or `key`). Only `key` if needed for object creation (then no `drop`/`store`). Compiler enforces consumption in same PTB.

**36. PTB Price Manipulation — Atomic Multi-Step Attack**

- **D:** Sui PTBs allow up to 1024 operations in a single atomic transaction. Attacker can: (1) borrow from pool A, (2) manipulate oracle/pool price, (3) execute vulnerable operation at manipulated price, (4) repay — all atomically.
- **FP:** Oracle uses TWAP or external feed (not manipulable in single tx). Price change limits per transaction. Multi-block time requirements between dependent operations.

**37. MEV via Shared Object Transaction Ordering**

- **D:** Validators can order transactions on shared objects. Attacker or colluding validator front-runs profitable transactions (sandwich attacks on DEX swaps, liquidation sniping).
- **FP:** Slippage protection with user-specified `min_amount_out`. Deadline parameter enforced. Batch processing that prevents front-running. Off-chain commit-reveal scheme.

**38. Missing Pause/Emergency Stop Mechanism**

- **D:** Protocol has no pause capability. When a vulnerability is discovered, there's no way to halt operations while a fix is deployed. Attacker drains the protocol during the response window.
- **FP:** Pause flag in shared config object. All public functions check: `assert!(!config.paused)`. Admin capability required to pause/unpause. Emergency function for immediate pause.

**39. Pause Flag Not Checked on All Functions**

- **D:** Protocol has a pause mechanism but not all critical functions check it. Attacker uses an unpaused function to drain funds during a "paused" state.
- **FP:** Every public entry function checks pause flag. Test coverage verifies all functions respect pause. Pause flag checked in shared helper function called by all handlers.

**40. Clock Object Not Used for Time-Sensitive Operations**

- **D:** Time-dependent logic (vesting, lockups, deadlines, oracle staleness) uses a hardcoded value or doesn't use `Clock` at all. Without `Clock`, there's no reliable on-chain time reference.
- **FP:** `clock::timestamp_ms(&clock)` used for all time-dependent logic. Clock passed as `&Clock` parameter (shared object at `0x6`). Timestamps stored and compared correctly.

**41. Clock Timestamp Granularity Assumption**

- **D:** Code assumes millisecond-precise execution timing. Sui's `Clock` provides epoch-level granularity — multiple transactions within the same epoch share the same timestamp. Time-sensitive arbitrage or ordering assumptions may be invalid.
- **FP:** Logic tolerant of same-timestamp transactions. No critical ordering dependent on sub-epoch time differences. Sequence numbers used instead of timestamps for ordering.

**42. Missing Deadline on Time-Sensitive Operations**

- **D:** Swap, deposit, or other time-sensitive operation has no deadline parameter. Transaction sits in the network, executes at a much later time at stale prices or unfavorable conditions.
- **FP:** `deadline_ms` parameter required: `assert!(clock::timestamp_ms(&clock) <= deadline_ms)`. User controls maximum execution time.

**43. Upgrade Capability Not Secured**

- **D:** `UpgradeCap` for the package held by a single key without timelock or multi-sig. Compromised key can deploy malicious code immediately, draining all protocol funds.
- **FP:** UpgradeCap held by multi-sig or governance. Timelock on upgrades. UpgradeCap destroyed (package made immutable). Upgrade policy restricts allowed changes.

**44. Package Made Immutable Prematurely**

- **D:** `UpgradeCap` destroyed too early (package made immutable). Critical bug discovered post-deployment cannot be fixed. All funds and state are permanently locked in buggy logic.
- **FP:** Immutability is intentional and documented. Upgrade path planned before immutability. Emergency governance mechanism exists.

**45. Upgrade Policy Too Permissive**

- **D:** Package upgrade policy allows `compatible` or `additive` changes when only `dep_only` is needed. Overly permissive policy means upgrades can change public function signatures, potentially breaking integrators or introducing vulnerabilities.
- **FP:** Upgrade policy set to minimum required level. Policy documented and justified. Governance approval required for policy changes.

**46. State Migration Missing After Upgrade**

- **D:** Package upgraded with new struct fields or logic changes, but existing on-chain objects not migrated. Old objects processed by new code with uninitialized or default values for new fields.
- **FP:** Migration function updates all existing objects to new version. Default values for new fields are safe. Version check prevents old objects from being processed by new code without migration.

**47. Reinitialization via Upgrade**

- **D:** Upgrade introduces a new "init-like" function that re-creates capabilities or resets state. Attacker (or malicious upgrader) calls it to create duplicate admin capabilities or reset protocol to initial state.
- **FP:** Init-like functions require existing admin capability. One-time guards prevent re-execution. Version check blocks re-initialization.

**48. Dynamic Dispatch via Generics — Unexpected Behavior**

- **D:** Generic function `process<T: store>(item: T)` accepts any type with `store`. Attacker passes an unexpected type that satisfies the constraint but causes unintended behavior when processed.
- **FP:** Type parameter constrained to specific types via phantom type on container. Type registry validates allowed types. Function logic type-agnostic and safe for any conforming type.

**49. Shared Object Config Update Without Timelock**

- **D:** Protocol configuration (fee rates, interest rates, collateral factors, oracle addresses) in a shared object updateable instantly by admin. Malicious or compromised admin makes a value-extracting config change with no warning.
- **FP:** Config updates have timelock (changes proposed, then executed after delay). Config update events emitted for monitoring. Range validation on all config values.

**50. Rate Limit Not Implemented on Value-Extracting Operations**

- **D:** Large withdrawals, liquidations, or transfers have no per-epoch or per-transaction rate limit. Attacker drains the entire protocol in a single transaction.
- **FP:** Per-epoch withdrawal limits enforced. Per-transaction maximum amount. Circuit breaker pauses protocol on abnormal outflows.

**51. Concurrent Shared Object Mutation — Lost Update**

- **D:** Two transactions read the same shared object value, each compute a new value, both write back. The second write overwrites the first — a classic lost update. Example: two deposits each read `total = 100`, add their amounts, both write back — second deposit "erases" the first.
- **FP:** Atomic read-modify-write pattern. Version/sequence check prevents stale writes. Sui's object versioning catches conflicts at consensus level.

**52. Hot Potato Used Across Module Boundary**

- **D:** Hot potato (receipt) struct created in one module but consumed in another, and the consuming module doesn't properly validate the receipt's contents. Attacker creates a fake receipt from a malicious module.
- **FP:** Receipt struct defined in the same module as creation and consumption. Module-level access control on receipt consumption. Receipt contents validated (amount, pool_id, etc.).

**53. Borrow-Return Mismatch in Hot Potato**

- **D:** Flash loan receipt records the borrowed amount, but the repay function doesn't validate that the returned amount matches or exceeds the receipt amount. Borrower repays less than borrowed.
- **FP:** Repay function validates: `assert!(returned_amount >= receipt.amount + fee)`. Receipt amount immutable. Balance checked after repayment.

**54. Missing Abort on Invalid State Transition**

- **D:** State machine transition (e.g., Active → Liquidating → Closed) doesn't abort on invalid transitions. Attacker transitions from Closed back to Active, reactivating a settled position.
- **FP:** Explicit state enum with transition validation. `assert!(obj.state == EXPECTED_STATE)` on every operation. Invalid transitions abort with descriptive error.

**55. Shared Object Accessed After Ownership Transfer**

- **D:** Object transferred from shared to owned (or vice versa), but other parts of the code still reference it as if it were in its original state. Access fails at runtime.
- **FP:** Ownership transitions documented and tested. References updated after ownership change. No shared-to-owned transitions (Sui doesn't allow this after initial sharing).

**56. Missing Idempotency Guard**

- **D:** Operation that should only execute once (claim, initialize, finalize) has no guard against repeated execution. Attacker calls it multiple times to extract value repeatedly.
- **FP:** Boolean flag: `assert!(!obj.claimed)` then `obj.claimed = true`. One-time object consumed on execution. Sequence/nonce prevents replay.

**57. Epoch-Based Logic Off-by-One**

- **D:** Logic comparing epochs uses `>=` where `>` is needed (or vice versa), allowing operations one epoch too early or too late. Affects vesting, lockups, and time-gated operations.
- **FP:** Epoch comparisons tested at boundary conditions. Clear documentation of inclusive vs exclusive bounds. `>=` vs `>` choice intentional and documented.

**58. Gas Exhaustion via Unbounded Operation**

- **D:** Function iterates over an unbounded collection (vector, table entries, dynamic fields) without a limit. When the collection grows large, the transaction exceeds the gas limit, permanently DoS-ing the operation.
- **FP:** Iteration bounded by constant or parameter. Pagination pattern used. `TableVec` with batch processing. Maximum collection size enforced on insertion.

**59. Cross-Module Reentrancy via PTB**

- **D:** Module A calls Module B within a PTB, and Module B calls back into Module A with state partially updated. While Move's resource model prevents classic reentrancy, PTBs enable multi-step interactions where ordering matters.
- **FP:** State fully updated before any cross-module call. No callbacks possible from called module. Operations are commutative (order doesn't matter).

**60. Validator-Controlled Transaction Ordering Exploitation**

- **D:** Validator controls the ordering of transactions touching the same shared object within an epoch. Colluding validator front-runs profitable operations or delays liquidations.
- **FP:** Operations protected by slippage/deadline parameters. Protocol doesn't depend on fair ordering. MEV-resistant design (commit-reveal, batch auctions).
