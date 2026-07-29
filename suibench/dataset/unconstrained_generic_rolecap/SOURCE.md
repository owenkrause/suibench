# unconstrained_generic_rolecap — Source provenance

Confirmed-tier entry. Class 2 (abilities & types), sub-class: unconstrained generic /
phantom-type not enforced.

## Provenance
- **provenance-tier: named-lab**
- **disclosure-date: 2024** (Monethic Sui Move security workshop material)
- **Source:** Monethic `sui-vuln-lab`, lab `access_control_3`, module `vuln_lab::phantom_role_bug`.
  - Writeup: https://medium.com/@monethic/sui-move-security-workshop-writeup-material-480c5e7d1da3
  - Code: https://github.com/Monethic/sui-vuln-lab/blob/main/vulnlab/sources/access_control_3/access_control_3.move
- **Class:** privilege escalation via an unconstrained generic role-capability parameter (the phantom
  type param that is supposed to encode privilege is never enforced).

## Vulnerability
`grant_admin<R>(_cap: &RoleCap<R>, ...)` is generic over the role marker `R` and returns a
`RoleCap<AdminRole>`. It is meant to require the caller to already hold an admin cap
(`&RoleCap<AdminRole>`), but because `R` is unconstrained, a `RoleCap<UserRole>` — obtainable for free
by anyone via `request_user_cap` — satisfies the signature and mints a privileged admin cap. This
mirrors the lab's `moderator_checkout_admin<R>` (should require `RoleCap<ModRole>`, is generic in `R`,
so a `RoleCap<UserRole>` escalates to `RoleCap<AdminRole>`).

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** The `Monethic/sui-vuln-lab` repo has **no LICENSE file** (all-rights-reserved), so
  the entry re-implements the documented mechanism faithfully rather than vendoring the lab verbatim.
  The bug — a role-cap accessor generic over the role type instead of binding it to the required role —
  is reproduced exactly; the surrounding scaffolding (a `Treasury` + admin-gated `withdraw` giving the
  escalation a concrete impact) is a minimal faithful reconstruction.

## Decontamination
- Package/address `challenge`; module `access_control`. No vuln/lab/fix-naming comments in `sources/`
  (the bug is the generic signature itself, visible in code). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
