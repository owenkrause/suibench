// The decision-maker port. A `Policy` is handed one `Observation` and returns
// one `Action`. The real agent loop (a driver that calls `act` in a loop) lives
// outside the kernel; the kernel only knows this seam.
//
// Reward-hacking control: the `Action` union carries NO `ChainSnapshot`. A
// policy therefore has no channel to supply or forge on-chain proof — a
// `confirmed` verdict is constructible only from a `Grader`-produced snapshot,
// never from anything the policy emits.
import type { Observation, Action } from "../kernel/types.js";

export interface Policy {
  act(o: Observation): Promise<Action>;
}
