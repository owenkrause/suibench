// Memoizes initGrading() so the schema is created once per process, no
// matter how many submission requests race to call ensureReady(). If
// initGrading() rejects (e.g. a transient DB hiccup), the memo is cleared so
// the NEXT call retries instead of replaying the same cached rejection
// forever (which would brick submissions until a process restart).
import { initGrading } from "./grading-runner.js";

let p: Promise<void> | undefined;

export const ensureReady = (): Promise<void> => {
  if (!p) {
    p = initGrading().catch((e) => {
      p = undefined;
      throw e;
    });
  }
  return p;
};
