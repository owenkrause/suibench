// Deterministic Policy adapters — no model, no sandbox. These let Task 5 be
// tested WITHOUT Docker or a live API: drive the same `Policy` seam the driver
// (`collectReports`) uses, but from a fixed script / recorded trajectory.
//
//  - ScriptedPolicy: emits a fixed `Action[]`, then a terminal sentinel.
//  - ReplayPolicy: replays the reports of a recorded `Trajectory`.
//
// The reward-hacking invariant still holds: neither can emit a `ChainSnapshot`
// (the `Action` union has no such member), so neither can fabricate proof.
import type { Policy } from "../ports/index.js";
import type { Trajectory } from "../ports/store.js";
import type { Action } from "../kernel/types.js";

/**
 * Replays a fixed action list, one per `act()`, then a terminal sentinel so the
 * driver's collect loop halts. Deterministic and replayable by construction.
 */
export class ScriptedPolicy implements Policy {
  private i = 0;
  constructor(private readonly actions: Action[]) {}
  async act(): Promise<Action> {
    if (this.i < this.actions.length) return this.actions[this.i++];
    return { kind: "run_bash", command: ":" }; // terminal sentinel
  }
}

/**
 * Replays a recorded {@link Trajectory}: emits each recorded step's `action` in
 * order, then a terminal sentinel. A recorded run replays to the exact same
 * action stream — the basis for determinism tests and regression fixtures
 * without re-invoking a model.
 */
export class ReplayPolicy implements Policy {
  private readonly actions: Action[];
  private i = 0;
  constructor(trajectory: Trajectory) {
    this.actions = trajectory.steps.map((s) => s.action);
  }
  async act(): Promise<Action> {
    if (this.i < this.actions.length) return this.actions[this.i++];
    return { kind: "run_bash", command: ":" };
  }
}
