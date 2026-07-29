# signature_unbound_coin_type — Source provenance

Confirmed-tier entry. Layer 2 (business logic), family: signature authorization — a signed
message that omits the coin type, enabling cross-coin replay. **Confirmability: `confirmable-value`** —
the attacker drains a valuable coin reserve by replaying a cheap-coin signature (adversary = player holding
a valid signature; victim = the game / other players).

## Provenance
- **provenance-tier: named-audit** (Major)
- **disclosure-date: 2023–2024** (MoveBit Mini Miners audit)
- **Source:** MoveBit — Mini Miners audit, finding **6.5** (`game.move#L206`,
  github.com/blocklords/sui-miner-smartcontracts): the signed `PackMessage` omits the coin type and the
  generic `COIN` is unbound to the signature, so one verifier signature is replayable across any coin the
  game holds.
- **Class:** signature/authorization payload not bound to the generic type it authorizes → cross-coin replay.

## Vulnerability
`sell_pack<COIN>` verifies a server ed25519 signature over `PackMessage { pack_id, amount, nonce }` — which
does not include `COIN` — before paying `amount` out of a `Game<COIN>` reserve. A signature issued for a
cheap coin's sale is byte-identical for a valuable coin's, so the attacker replays it against
`sell_pack<ValuableCoin>` and drains the valuable reserve.

## VERBATIM vs RE-AUTHORED
- **RE-AUTHORED.** A faithful minimal reconstruction: a shared `Server` signing key, per-coin `Game<COIN>`
  reserves, and a `sell_pack<COIN>` that verifies a signature over a `PackMessage` omitting the coin type.
  Uses the real `sui::ed25519::ed25519_verify` + `std::bcs::to_bytes` so the missing type-binding is faithful.

## Decontamination
- Package/address `challenge`; module `game`. No vuln/audit/fix-naming comments in `sources/` (the bug is the
  `PackMessage` shape omitting `COIN` in the signed `bytes`). Edition `2024`. Builds clean with
  `sui move build --build-env mainnet`.
