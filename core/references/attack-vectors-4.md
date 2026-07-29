# Attack Vectors Reference — Oracle, DeFi Protocol & Platform-Level (4/4)

> Part 4 of 5 · Vectors 91–120 of 143 total
> Covers: oracle manipulation, DeFi protocol patterns, staking/rewards, liquidation, dependency risks, ZK/TEE, agent security

---

**91. Stale Oracle Price**

- **D:** Oracle price feed used without checking the `last_update` or `publish_time` timestamp. Oracle may have stopped updating — attacker exploits stale price to borrow at outdated collateral value or liquidate at favorable prices.
- **FP:** Staleness check: `assert!(clock_ms - oracle.last_update_ms <= MAX_STALE_MS)`. MAX_STALE configurable by admin. Price rejected if stale.

**92. Oracle Confidence Interval Not Validated**

- **D:** Oracle price used without checking confidence width. Wide confidence means unreliable price — attacker uses the uncertain price to extract value.
- **FP:** Confidence check: `assert!(oracle.conf * 100 / oracle.price <= MAX_CONF_PCT)`. Threshold admin-configurable. Price rejected if confidence too wide.

**93. Fake Oracle Account — Missing Source Validation**

- **D:** Oracle object accepted without validating it was created by the trusted oracle program (Pyth, Switchboard, Supra). Attacker creates a fake oracle object with manipulated prices.
- **FP:** Oracle object ID stored in config and validated: `assert!(object::id(oracle) == config.oracle_id)`. Oracle owner module validated. Hardcoded oracle addresses.

**94. Single Oracle Source — No Redundancy**

- **D:** Protocol relies on a single oracle feed. If that feed is manipulated, delayed, or goes offline, the protocol operates on bad data or is completely DoS-ed.
- **FP:** Multi-oracle aggregation (median of 3+ sources). Deviation check between oracle sources. Fallback oracle configured.

**95. Flash Loan Price Manipulation**

- **D:** Protocol uses spot pool price or reserve ratio for valuation. Attacker uses a PTB to: (1) borrow via flash loan, (2) manipulate pool price, (3) execute at manipulated price, (4) repay — all atomically.
- **FP:** TWAP or external oracle used instead of spot. Price manipulation detection (deviation check). Multi-epoch time requirement between price-dependent operations.

**96. Retroactive Oracle Pricing**

- **D:** Current oracle price used to settle positions opened at a different price. Instead of storing reference price at open time, protocol uses live price at settlement.
- **FP:** Reference price stored in position object at open time. Settlement uses stored price. Price updates only affect new positions.

**97. On-Chain Price as Slippage Reference**

- **D:** Slippage protection uses an on-chain price (oracle, pool spot) instead of user-provided expected price. Attacker manipulates on-chain price, then the "slippage check" passes against the manipulated reference.
- **FP:** Slippage parameter from user calldata (`min_amount_out`, `max_price`). Off-chain price used as reference. TWAP for slippage reference.

**98. Vault Share Inflation — First Depositor Attack**

- **D:** Empty vault allows first depositor to mint 1 share, donate tokens to inflate share price. Second depositor's deposit truncates to 0 shares. First depositor redeems everything.
- **FP:** Virtual shares/assets offset. Minimum first deposit. Dead shares minted on init. `assert!(shares > 0)`.

**99. Staking Reward Accumulator Not Updated Before Balance Change**

- **D:** Staking contract doesn't update reward accumulator (`reward_per_token`) before stake/unstake. New staker gets credit for rewards earned before they staked.
- **FP:** Accumulator updated before any balance change. `update_rewards()` called first in stake/unstake. Checkpoint pattern implemented.

**100. Flash Stake/Unstake Reward Capture**

- **D:** No minimum staking duration. Attacker stakes immediately before reward distribution, captures the reward, and unstakes in the same epoch.
- **FP:** Minimum staking/lockup period enforced. Time-weighted rewards. Snapshot from past epoch.

**101. Reward Dilution via Direct Transfer**

- **D:** Reward rate based on coin balance in the reward pool rather than internal accounting. Attacker sends tokens directly to the pool, inflating the balance and diluting or manipulating the reward rate.
- **FP:** Internal accounting (`total_staked` state variable) used for reward calculation. Direct transfers don't affect reward math.

**102. Precision Loss Zeroing Small Stakers**

- **D:** Reward calculation for small stakers rounds to zero: `(small_stake * reward_rate) / total_stake = 0`. Small stakers earn zero while their stake dilutes others.
- **FP:** High-precision accumulator (u128/u256). Minimum stake above precision threshold. Accumulated reward tracking.

**103. Liquidation Incentive Insufficient for Small Positions**

- **D:** Percentage-based liquidation bonus on dust positions doesn't cover transaction cost. Positions become permanently unliquidatable, accumulating bad debt.
- **FP:** Minimum position size enforced. Fixed minimum liquidation bonus. Dust position auto-liquidation by protocol.

**104. Self-Liquidation Profitable**

- **D:** User liquidates their own position and profits from the liquidation bonus exceeding the penalty.
- **FP:** Self-liquidation prohibited. Bonus < penalty. Health factor check prevents liquidation of healthy positions.

**105. Interest Accrual During Pause**

- **D:** Protocol pauses operations but interest continues accruing. On unpause, users face unexpected charges or liquidation from accumulated interest.
- **FP:** Interest accrual paused alongside operations. Accumulated interest during pause capped or forgiven.

**106. Bad Debt Not Socialized**

- **D:** Liquidation leaves residual debt (collateral < debt). The bad debt is not socialized — it sits in the protocol indefinitely, creating an accounting hole.
- **FP:** Bad debt socialization mechanism: spread across insurance fund, then all depositors. Automatic bad debt write-off. Insurance fund maintained.

**107. Unaudited Dependency — Library Vulnerability**

- **D:** Protocol imports an unaudited third-party library that contains a vulnerability (overflow, backdoor, incorrect rounding). The vulnerability propagates to the caller.
- **FP:** All dependencies audited. Library version pinned and reviewed. Internal implementations for critical math. Dependency audit registry.

**108. Dependency Version Not Pinned**

- **D:** Move.toml references a git dependency without a specific revision or tag. The dependency can change (main branch updated), introducing breaking changes or vulnerabilities without the protocol's knowledge.
- **FP:** Dependency pinned to specific git revision or tag. Lock file used. Dependency updates reviewed.

**109. Backdoor in Imported Module**

- **D:** Imported module contains a public init or admin function that the importing protocol doesn't expect. Attacker calls the backdoor function to mint capabilities or extract funds.
- **FP:** All imported module functions reviewed. Only specific functions called. Module source code audited.

**110. ZK Proof Replay — Missing Nullifier**

- **D:** ZK-proof verified on-chain but no nullifier tracked. Attacker replays the same proof multiple times to execute the same action repeatedly (double-spend, double-claim).
- **FP:** Nullifier stored in `Table`: `assert!(!table::contains(&nullifiers, proof.nullifier))`. Nullifier added after successful verification.

**111. ZK Proof Intent Mismatch**

- **D:** ZK-proof validates a computation but the public inputs don't bind to the on-chain action parameters. Attacker uses a valid proof for a different action than intended.
- **FP:** Public inputs include all action parameters (amount, recipient, epoch). Hash of parameters verified against proof. Intent hash validated.

**112. TEE Attestation Not Verified**

- **D:** Trusted Execution Environment (TEE) computation result accepted without verifying the attestation report. Attacker submits fake computation results.
- **FP:** Attestation report validated on-chain. Report freshness checked. Report data hash matches input hash.

**113. Agent Delegated Capability Abuse**

- **D:** AI agent holds a delegated capability (spend cap, trade authority) with no on-chain intent verification. Agent (compromised or prompt-injected) performs unauthorized actions.
- **FP:** Every agent action requires on-chain intent proof. Spend limits enforced immutably on-chain. Capability scoped (time, amount, target limited).

**114. Agent Memory Poisoning Leading to Bad Transactions**

- **D:** Adversarial input poisoning an AI agent's context (LLM context or RAG database), causing it to execute harmful transactions (approving malicious contracts, draining funds).
- **FP:** Verified intent proof required before every transaction. Agent transactions human-approved. Context isolation between agent sessions.

**115. Multi-Agent Consensus Failure**

- **D:** Multi-agent system accepts votes without signature verification. Rogue agent injects unverified votes, triggering unauthorized protocol actions.
- **FP:** Agent signatures verified on-chain. Agent membership validated. Quorum requires verified, distinct agents.

**116. Kiosk NFT Extraction Without Transfer Policy**

- **D:** Agent or user with `KioskOwnerCap` extracts NFTs directly from Kiosk without completing the transfer policy (bypassing royalties, allowlist checks).
- **FP:** `transfer_policy` enforced on all extractions. `kiosk::has_access()` verified. Transfer rules applied.

**117. Missing Invariant Check on Critical Operation**

- **D:** Protocol invariant (e.g., `total_borrows <= total_deposits + yield`, `sum(balances) == total_supply`) not checked after a state-modifying operation. Violation goes undetected, creating exploitable accounting hole.
- **FP:** Invariant assertions at end of every state-modifying function. Invariant violation aborts the transaction. Invariants tested extensively.

**118. Programmable Transaction Block Exceeds Complexity Limit**

- **D:** Complex protocol operation requires so many PTB steps that it exceeds Sui's transaction limits (gas, input count, command count). Operation becomes permanently unexpecutable.
- **FP:** Operations designed to fit within single-PTB limits. Batch/pagination for complex operations. Gas budget tested for worst case.

**119. Missing Slippage Protection on DEX Swap**

- **D:** Swap function has no user-provided minimum output amount. MEV bots sandwich the swap, extracting value from the trader.
- **FP:** `min_amount_out` parameter required and enforced. Deadline parameter prevents stale execution. Price impact limit.

**120. Package Upgrade Authority Single Point of Failure**

- **D:** `UpgradeCap` held by a single EOA. Compromised key deploys malicious upgrade, draining all protocol funds. Highest-impact vector for upgradeable packages.
- **FP:** UpgradeCap held by multi-sig or governance. Timelock on upgrades. Package immutable (UpgradeCap destroyed). Verifiable build.
