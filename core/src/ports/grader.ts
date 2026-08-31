// The confirmer seam. The networked confirmer (boot localnet, run the entry's
// `harness/setup.ts` to seed initial state, capture the post-setup baseline,
// publish the mounted sources, run the attack script, and — for availability
// entries — run the victim op) lives behind THIS port. It is the ONLY producer
// of a `ChainSnapshot` in the whole system: a snapshot exists iff a `Grader` ran
// a script against a mount and captured the committed result. Nothing else — no
// policy, no verdict constructor — can mint one, which is what makes a
// `confirmed` verdict unforgeable.
//
// `runOnMount` returns the full gradeable evidence — a `ChainDelta`, the
// per-boot `CheckParams` (packageId + funded role addresses), and the
// attack-phase `CheckEvidence` (drained digest provenance + successful-tx
// events) the snapshot-pure `Check` needs. All three are known only to the
// grader: it boots the localnet, runs `setup.ts`, publishes the mount, drains
// the attack phase's committed digests, and fetches their status/events from
// the trusted host-side client. Returning them together keeps the driver on
// this port (no reach into a concrete grader).
//
// `pre` is committed state AFTER setup, BEFORE the attack; `post` is committed
// state AFTER the attack (with any victim outcome folded in). An exploit that
// does NOT land — the normal "fails under patch" counterfactual outcome — is
// not an error: the grader still returns evidence (an unchanged `post`, and an
// evidence set showing no successful attack transaction), and the check
// returns an empty witness set. `runOnMount` throws ONLY on genuine infra
// failure (can't boot/publish/capture/drain), never on a routine exploit
// outcome.
import type { ChainDelta, MoveFile } from "../kernel/types.js";
import type { CheckParams, CheckEvidence } from "../kernel/checks.js";
import type { Mount } from "./sandbox.js";

/** Everything a `Check` needs to grade one run: the committed before/after
 *  pair, the per-boot params (packageId + role addresses) that name what to
 *  look for, and the attack-phase evidence (drained digests + events). The
 *  grader produces all three — the params and evidence are not entry-static
 *  because each variant publishes fresh and attacks independently. */
export interface GraderResult {
  readonly delta: ChainDelta;
  readonly params: CheckParams;
  readonly evidence: CheckEvidence;
}

export interface Grader {
  runOnMount(mount: Mount, script: MoveFile): Promise<GraderResult>;
}
