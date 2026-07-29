import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { transformVersion } from "../perturbation/version.js";

const execFileAsync = promisify(execFile);

export interface RunManifest {
  sui_version: string | null;
  image_id: string | null;
  node_version: string;
  mysten_sui_version: string | null;
  git_commit: string | null;
  perturbation?: { transform_version: string; seed_rule: string; twins_per_entry: number };
}

export interface ManifestDeps {
  run: (cmd: string, args: string[]) => Promise<string>;
  readPackageJson: () => string | null;
}

const defaultDeps: ManifestDeps = {
  async run(cmd, args) {
    const { stdout } = await execFileAsync(cmd, args, { timeout: 30_000 });
    return stdout;
  },
  readPackageJson() {
    try {
      return readFileSync(resolve(import.meta.dirname, "../../package.json"), "utf-8");
    } catch {
      return null;
    }
  },
};

async function tryRun(deps: ManifestDeps, cmd: string, args: string[]): Promise<string | null> {
  try {
    return (await deps.run(cmd, args)).trim();
  } catch {
    return null;
  }
}

function mystenSuiVersion(raw: string | null): string | null {
  if (!raw) return null;
  try {
    const pkg = JSON.parse(raw) as { dependencies?: Record<string, string> };
    return pkg.dependencies?.["@mysten/sui"] ?? null;
  } catch {
    return null;
  }
}

function tryReadPackageJson(deps: ManifestDeps): string | null {
  try {
    return deps.readPackageJson();
  } catch {
    return null;
  }
}

export async function captureManifest(
  image: string,
  deps: ManifestDeps = defaultDeps,
): Promise<RunManifest> {
  return {
    sui_version: await tryRun(deps, "docker", ["run", "--rm", "--entrypoint", "sui", image, "--version"]),
    image_id: await tryRun(deps, "docker", ["image", "inspect", "--format", "{{.Id}}", image]),
    node_version: process.versions.node,
    mysten_sui_version: mystenSuiVersion(tryReadPackageJson(deps)),
    git_commit: await tryRun(deps, "git", ["rev-parse", "HEAD"]),
  };
}

export function perturbationManifest(twinsPerEntry: number): NonNullable<RunManifest["perturbation"]> {
  return {
    transform_version: transformVersion(),
    seed_rule: "sha256(target + '#' + index)",
    twins_per_entry: twinsPerEntry,
  };
}
