// Pure rules for the untrusted-image filesystem scrub (§9.1 invariant 4). Given
// ordinary /workspace paths plus any first-party package roots found under
// node_modules, return the ones that violate the invariant. Deliberately NOT a bare
// `sources/` check — the .move framework cache legitimately ships Move `sources/`,
// and it lives in $HOME, outside the scanned /workspace.
const DATASET_MARKERS = [/\/dataset\//, /\/entry\.json$/, /\/check\.ts$/, /\/SOURCE\.md$/];
const HARNESS_MODULES = [
  /\/dist\/adapters\/(confirmer|parse|judge)[^/]*$/,
  /\/dist\/bench\/(driver|prompt)[^/]*$/,
];
const FIRST_PARTY_PACKAGES = [/\/node_modules\/(core|suibench|suixploit)(?:\/|$)/];

export function classifyScrub(paths: string[]): { forbidden: string[] } {
  const rules = [...DATASET_MARKERS, ...HARNESS_MODULES, ...FIRST_PARTY_PACKAGES];
  return { forbidden: paths.filter((p) => rules.some((r) => r.test(p))) };
}
