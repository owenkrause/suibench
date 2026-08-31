// The phase container's least-privilege context (§5.2/§9.1): the attacker keypair
// and the public facts an exploit legitimately needs, NEVER admin/user keys — those
// stay in the confirmer container. Addresses are public; only the keys are secret.
export function scopeAttackerContext(full: Record<string, string>): string {
  const { packageId, attackerAddress, adminAddress, userAddress, benchmarkStartCheckpoint, attackerKeyPair } = full;
  return JSON.stringify({
    packageId, attackerAddress, adminAddress, userAddress, benchmarkStartCheckpoint, attackerKeyPair,
  });
}
