// Assert the built untrusted-runtime image satisfies §9.1 invariant 4 (no answer
// key or first-party grader packages) AND that its toolchain is intact. Run against a built
// image: `pnpm --filter suibench verify:image-scrub`. Exits non-zero on any failure.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { UNTRUSTED_IMAGE } from "../src/adapters/images.js";
import { classifyScrub } from "./image-scrub.js";

const run = promisify(execFile);

async function inImage(cmd: string): Promise<string> {
  const { stdout } = await run(
    "docker",
    ["run", "--rm", "--entrypoint", "bash", UNTRUSTED_IMAGE, "-lc", cmd],
    { maxBuffer: 64 << 20 },
  );
  return stdout;
}

async function main(): Promise<void> {
  const failures: string[] = [];

  // Scan ordinary workspace paths plus any first-party package root nested in
  // node_modules. The second find catches pnpm's physical virtual-store copies,
  // not just its top-level symlinks.
  const listing = await inImage(
    "find /workspace -path /workspace/node_modules -prune -o -print; " +
    "find /workspace/node_modules \\( " +
    "-path '*/node_modules/core' -o " +
    "-path '*/node_modules/suibench' -o " +
    "-path '*/node_modules/suixploit' \\) -print",
  );
  const paths = listing.split("\n").map((s) => s.trim()).filter(Boolean);
  const { forbidden } = classifyScrub(paths);
  if (forbidden.length) failures.push(`forbidden paths present:\n  ${forbidden.join("\n  ")}`);

  // Toolchain presence — each check by EXIT CODE, independently. Do NOT stringify a
  // failed exec and search it for tokens: the error text includes the command line
  // (with the very tokens), so a totally broken toolchain would read as OK. inImage
  // throws on a nonzero exit, so a throw here IS the failure signal.
  const checks: Array<[string, string]> = [
    ["sui CLI", "sui --version >/dev/null 2>&1"],
    [".move cache", 'test -d "$HOME/.move/git"'],
    ["tsx", "test -x /workspace/node_modules/.bin/tsx"],
    ["@mysten/sui resolvable", 'cd /workspace && node --input-type=module -e "await import(\\"@mysten/sui/grpc\\")"'],
  ];
  for (const [name, cmd] of checks) {
    try {
      await inImage(cmd);
    } catch {
      failures.push(`toolchain check failed: ${name}`);
    }
  }

  if (failures.length) {
    console.error(`IMAGE SCRUB FAILED for ${UNTRUSTED_IMAGE}:\n${failures.join("\n")}`);
    process.exit(1);
  }
  console.log(`IMAGE SCRUB OK — ${UNTRUSTED_IMAGE}: no answer key / harness / first-party packages, toolchain intact.`);
}

main().catch((e) => { console.error(e); process.exit(1); });
