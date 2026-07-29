# Attack Vectors Reference — Object Model, Abilities & Access Control (1/4)

> Part 1 of 5 · Vectors 1–30 of 143 total
> Covers: capability pattern, object abilities (copy/drop/store/key), visibility, access control, object leakage, type safety, transfer policies

---

**1. Missing Capability Check on Admin Function**

- **D:** Privileged function (withdraw, mint, pause, update config) callable without requiring a capability object (`AdminCap`, `TreasuryCapR`, `ManagerCap`). Any user can call the function and perform admin operations.
- **FP:** Capability parameter required (`_: &AdminCap` or `cap: &ManagerCap`). Address-based check with `assert!(ctx.sender() == admin)` present (weaker but acceptable). Function is `public(package)` visibility.

**2. Address-Based Access Control Instead of Capability**

- **D:** Access control relies on `ctx.sender() == @admin_address` instead of the capability object pattern. Hardcoded addresses break on package upgrades and are inflexible for role delegation.
- **FP:** Design explicitly requires address-based control with documented rationale. Capability pattern used instead. Address stored in a mutable config object (not hardcoded).

**3. Object Has `copy` Ability — Token Duplication**

- **D:** A value-bearing object (coin, NFT, badge, receipt) has the `copy` ability, allowing anyone to duplicate it. Attacker duplicates tokens to drain pools or mint unlimited supply.
- **FP:** Object is explicitly designed to be copyable (e.g., configuration data, read-only references). No value-bearing or authority implications. `copy` removed from struct definition.

**4. Object Has `drop` Ability — Debt/Obligation Destruction**

- **D:** An obligation object (debt record, flash loan receipt, collateral lock) has the `drop` ability. Borrower can silently destroy their debt without repaying, or destroy a collateral lock to unlock assets early.
- **FP:** Object has no financial obligation semantics. Hot potato pattern used (no `drop`, no `store`). `drop` intentionally allowed with documented rationale.

**5. Object Has `store` Ability — Unauthorized Wrapping**

- **D:** A sensitive object (capability, authority token) has `store`, allowing it to be wrapped inside another object and transferred or hidden. Attacker wraps a capability to move it outside the protocol's control.
- **FP:** `store` required for legitimate purposes (e.g., storing in dynamic fields). Transfer policies enforce correct handling. Object designed to be storable.

**6. Object Leakage via Public Function Return**

- **D:** A public function returns a capability or admin object that should remain with the protocol. Anyone calling the function captures the leaked privilege.
- **FP:** Return type is non-sensitive (data, computed value). Capability created in `init` and transferred to deployer only. Function is `public(package)`.

**7. Capability Created Outside init — Unrestricted Minting**

- **D:** Capability objects (AdminCap, TreasuryCap) created in a function other than `init`, allowing anyone to mint new capabilities. Attacker creates their own admin capability.
- **FP:** Capability creation is access-controlled (requires existing capability). Creation function is `public(package)`. One-time witness (OTW) pattern enforced.

**8. Missing One-Time Witness (OTW) Validation**

- **D:** Coin or token type created without using the one-time witness pattern. Without OTW, the `TreasuryCap` for the coin type can potentially be created by any module, enabling supply inflation.
- **FP:** `coin::create_currency` called with OTW (module name struct). `sui::types::is_one_time_witness` validated. Standard Sui coin creation pattern used.

**9. Public Entry Function Combination — Composability Break**

- **D:** Function declared as `public entry` instead of just `public` or just `entry`. The `public entry` combination prevents the function from being composed in PTBs in some contexts and creates confusing API semantics.
- **FP:** Function explicitly designed as both public and entry with documented rationale. Modern Sui version where this is properly handled.

**10. Internal Function Exposed as public Instead of public(package)**

- **D:** Function intended for internal use within the package declared as `public` instead of `public(package)`. External modules can call it, bypassing intended access restrictions.
- **FP:** Function is deliberately public for composability. All callers validated via capability checks. Function performs no sensitive operations.

**11. Missing has_one Equivalent — Object Relationship Not Validated**

- **D:** Function accepts two objects that should be related (e.g., a vault and its config, a position and its pool) but doesn't validate the relationship. Attacker passes mismatched objects.
- **FP:** Object IDs cross-referenced: `assert!(vault.pool_id == object::id(pool))`. PDA-like derivation validates relationship. Dynamic field lookup enforces parent-child relationship.

**12. Type Cosplay via Generic Type Parameter**

- **D:** Generic function accepts `T` without constraining it, allowing attacker to pass a different type than expected. E.g., `deposit<FakeToken>` instead of `deposit<USDC>` to credit the wrong balance.
- **FP:** Type constrained via phantom type on the pool/vault: `Pool<T>` ensures only matching `Coin<T>` accepted. Explicit type check against stored type identifier.

**13. Phantom Type Not Enforced on Coin Operations**

- **D:** Coin or balance operations don't leverage the phantom type parameter for safety. Different coin types can be mixed in the same pool or vault, breaking accounting.
- **FP:** `Coin<T>` and `Balance<T>` phantom types correctly partition all operations. Type parameters propagated through all function signatures.

**14. Transfer Without Policy — Capability Misdirection**

- **D:** Sensitive object transferred via `transfer::public_transfer` without a two-step or delayed transfer policy. Single-step transfer to a wrong address is irreversible, permanently losing protocol admin capability.
- **FP:** Two-step transfer wrapper used (initiate → accept). Delayed transfer with timelock. Object transferred only to verified addresses. `transfer::transfer` (non-public, owner-only) used.

**15. Missing Delayed Transfer on Admin Capability**

- **D:** Admin/treasury capability can be transferred instantly with no timelock. Compromised key or social engineering attack immediately transfers all admin power.
- **FP:** Delayed transfer wrapper with minimum delay (e.g., 24-48 hours). Multi-sig required for capability transfer. Governance vote required.

**16. Capability Stored in Shared Object — Uncontrolled Access**

- **D:** A capability object stored inside a shared object accessible to all users. Anyone can extract or use the capability through the shared object's public functions.
- **FP:** Capability stored in owned object (not shared). Access to capability within shared object gated by additional checks. Capability referenced by immutable reference only (`&Cap`).

**17. init Function Assumptions After Upgrade**

- **D:** Code assumes `init` will run again on package upgrade. In Sui, `init` only runs on first deployment — upgrades do NOT re-execute `init`. Post-upgrade initialization logic is missing.
- **FP:** Migration function exists for post-upgrade initialization. No state changes needed on upgrade. Version check pattern handles upgrade transitions.

**18. Upgrade Doesn't Update Dependencies**

- **D:** Package upgrade assumes dependent packages will also be updated. Sui package upgrades don't auto-update dependencies — old dependency versions remain in use.
- **FP:** Dependencies explicitly re-published and linked. Dependency versions checked at runtime. No breaking changes in dependencies.

**19. Missing Version Check on Shared Object**

- **D:** Shared object has no `version` field. After a package upgrade, old functions may still be called on objects, causing incompatible state transitions. No way to enforce "upgrade complete" semantics.
- **FP:** `version: u64` field present in all shared objects. Every public function checks: `assert!(obj.version == CURRENT_VERSION)`. Migration function increments version.

**20. Struct Field Reordering in Upgrade — Memory Layout Break**

- **D:** Package upgrade changes struct field order or removes fields. Objects created by the old version become incompatible, causing deserialization failures or data corruption.
- **FP:** Fields only appended (never reordered or removed). Optional fields used for forward compatibility. Version-based deserialization handles layout changes.

**21. Publisher Object Not Secured**

- **D:** `Publisher` object (created via OTW in `init`) not properly secured. Holder of Publisher can create `Display` objects and manage type metadata, potentially impersonating the protocol.
- **FP:** Publisher transferred to admin/governance on creation. Publisher stored in access-controlled object. Publisher capabilities limited by design.

**22. Kiosk/TransferPolicy Bypass**

- **D:** NFT transfer policy not enforced — NFTs extracted from Kiosk without completing required transfer policy rules (royalties, allowlist checks). Attacker bypasses royalty payments or transfer restrictions.
- **FP:** `transfer_policy::confirm_request` called with all required rules. Kiosk locked with `kiosk_lock` rule. Custom rules enforced in transfer policy.

**23. Display Object Manipulation**

- **D:** `Display` object for a type modifiable by unauthorized party, allowing spoofed metadata (fake names, images, descriptions) for tokens or NFTs.
- **FP:** Display creation requires Publisher. Display object owned by protocol admin. Display updates access-controlled.

**24. Unauthorized Object Freeze**

- **D:** Object frozen via `transfer::freeze_object` by an unauthorized user. Once frozen, the object becomes permanently immutable — legitimate owner can never modify it again.
- **FP:** Freeze operations gated by capability check. Objects frozen only during init or by admin. Object design doesn't support freezing.

**25. Unauthorized Object Sharing**

- **D:** Owned object converted to shared via `transfer::share_object` by unauthorized caller. Once shared, an owned object can never be made owned again — all users gain access.
- **FP:** Share operations gated by capability. Objects shared only during init. Shared status is intentional by design.

**26. Missing Event Emission for Critical State Changes**

- **D:** Critical operations (admin transfers, config updates, large withdrawals) don't emit events. Off-chain monitoring and indexers miss these changes, preventing timely response to attacks.
- **FP:** Events emitted for all state-changing operations. Event structs include all relevant fields. Events named in past tense (Transferred, Updated, Minted).

**27. Error Constants Not Unique**

- **D:** Same error code used for different failure conditions. When an error occurs, it's impossible to distinguish the root cause, making debugging and incident response difficult.
- **FP:** Each error constant has a unique numeric value. Error names follow `EPascalCase` convention. Error messages descriptive.

**28. Dynamic Field Not Cleaned Up Before Object Deletion**

- **D:** Parent object deleted without removing its dynamic fields. Orphaned dynamic fields become permanently inaccessible — their data and any stored value (including coins) are lost forever.
- **FP:** All dynamic fields removed before parent deletion. `dynamic_field::exists_` checked before removal. Cleanup function provided.

**29. Dynamic Object Field Exposes Wrapped Object**

- **D:** Sensitive object stored as a dynamic object field (not dynamic field). Dynamic object fields preserve the child's object ID, making it discoverable by indexers. Attacker can find and potentially interact with the "hidden" object.
- **FP:** `dynamic_field::add` used instead of `dynamic_object_field::add` for sensitive data. Object visibility is intentional. No sensitive data exposed.

**30. Missing Sui Object ID Validation**

- **D:** Function accepts an object by ID without validating it belongs to the expected type or protocol. Attacker passes an object from a different protocol with a compatible interface.
- **FP:** Object type enforced by function signature (`Account<'info, T>` equivalent). Object ownership validated. Dynamic field lookup validates parent.
