import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { transformVersion } from "../perturbation/version.js";

const execFileAsync = promisify(execFile);

// One role image's provenance: its name and immutable ID (so two different grading
// images can never produce indistinguishable reports).
export interface ImageRef {
  name: string;
  id: string | null;
  sui_version: string | null;
}

export interface RunManifest {
  images: { untrusted: ImageRef; confirmer: ImageRef; gate: ImageRef };
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

async function imageRef(deps: ManifestDeps, name: string): Promise<ImageRef> {
  // The recorded ID is the manifest's whole point (line 10). A missing image
  // inspects to null, which would record empty provenance AND — since docker's
  // default pull policy is `missing` — let a launch silently pull a stranger from
  // a registry. Fail loud instead: grading runs pinned, already-built images (the
  // launches also pass --pull=never so they refuse anything not present locally).
  const id = await tryRun(deps, "docker", ["image", "inspect", "--format", "{{.Id}}", name]);
  if (!id) {
    throw new Error(
      `image "${name}" not found locally — build it before grading; its provenance cannot be recorded`,
    );
  }
  return {
    name,
    id,
    sui_version: await tryRun(deps, "docker", ["run", "--rm", "--entrypoint", "sui", name, "--version"]),
  };
}

export async function captureManifest(
  images: { untrusted: string; confirmer: string; gate: string },
  deps: ManifestDeps = defaultDeps,
): Promise<RunManifest> {
  return {
    images: {
      untrusted: await imageRef(deps, images.untrusted),
      confirmer: await imageRef(deps, images.confirmer),
      gate: await imageRef(deps, images.gate),
    },
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
