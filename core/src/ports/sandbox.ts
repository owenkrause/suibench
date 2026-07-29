// The HUNT seam: an isolated execution environment the policy's tool calls run
// against. Only the source mount (a `SanitizedSource`) enters — no groundtruth,
// no label files — so contamination through the sandbox is unrepresentable.
import type { SanitizedSource } from "../kernel/types.js";

/** The only thing that may be mounted into a sandbox: a decontaminated source view. */
export type Mount = SanitizedSource;

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** The requested sandbox artifact does not exist; transport failures use other errors. */
export class SandboxFileNotFoundError extends Error {
  constructor(readonly path: string) {
    super(`sandbox file not found: ${path}`);
    this.name = "SandboxFileNotFoundError";
  }
}

export interface Sandbox {
  exec(cmd: string): Promise<ExecResult>;
  copyOut(path: string): Promise<Buffer>;
  /** Write bytes to a container path WITHOUT a shell, so a model-controlled path
   *  can't inject a command (unlike an `exec("echo … > path")`). */
  writeFile(path: string, content: string): Promise<void>;
  teardown(): Promise<void>;
}
