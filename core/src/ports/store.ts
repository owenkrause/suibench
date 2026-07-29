// The persistence seam. Records a run's trajectory (what the policy saw and did)
// so a run can be replayed deterministically. Lean by design: a trajectory is
// the observation/action pairs and the entry it graded — nothing ships here
// until a real consumer needs it.
import type { Observation, Action } from "../kernel/types.js";

export interface TrajectoryStep {
  observation: Observation;
  action: Action;
}

export interface Trajectory {
  id: string;
  target: string;
  steps: TrajectoryStep[];
}

export interface Store {
  record(t: Trajectory): Promise<void>;
  replay(id: string): Promise<Trajectory>;
}
