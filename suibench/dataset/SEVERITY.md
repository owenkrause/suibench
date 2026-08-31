# Severity rubric

Every `entry.json` labels its vuln `critical | high | medium | low`, assigned on
two axes: **impact** (worst outcome) and **preconditions** (what an attacker must
control or wait for).

| Tier | Criteria |
|------|----------|
| **critical** | Unprivileged attacker **directly** drains principal or mints unbacked value; the whole pool/vault is at risk; no special precondition beyond normal protocol state. |
| **high** | Fund loss that is **gated** — needs a specific market state or race, a victim to act, a privileged role to misbehave, or is bounded to fees/yield/residuals — **or** permanent DoS that freezes funds. |
| **medium** | Recoverable/temporary DoS, permanent fund-**lock with no attacker gain** (griefing), a latent missing safeguard that needs external conditions (e.g. a stale oracle plus a consumer that trusts it), or a fairness/advantage bounded to non-principal stakes. |
| **low** | Recoverable liveness griefing with an easy workaround and no fund loss, precision dust, informational, or self-inflicted only. |

"The pool holds funds" or "a user has a balance" is normal state, not a gating
precondition, so unprivileged theft against any ordinary user stays `critical`.
