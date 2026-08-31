# Per-role image matrix (spec §5.5). Fast to build on top of the heavy base
# toolchain (Sui CLI + Node + pnpm + baked Move framework cache). Build from the
# workspace root (this repo root):
#   docker build -f suibench/Dockerfile.base -t suibench-base .                              (once)
#   docker build -f suibench/Dockerfile --target confirmer         -t suibench-confirmer .        (per code change)
#   docker build -f suibench/Dockerfile --target untrusted-runtime -t suibench-untrusted-runtime .
# The third matrix image — the node:slim `gate` — is built from Dockerfile.gate.
#
# BUILD CONTEXT IS THE WORKSPACE ROOT (repo root), not suibench/ — the pnpm
# workspace + root lockfile live there and must be visible so we can prune a
# self-contained deploy for suibench. The packages live at the repo root.
#
# Why `pnpm deploy` (not `COPY package.json && pnpm install --frozen-lockfile`)?
# Under the pnpm workspace there is no package-local lockfile (the lock lives at
# the workspace root and covers all packages), so that recipe can't resolve
# suibench's deps in isolation. `pnpm deploy` produces a PRUNED, self-contained
# node_modules for one workspace package (its runtime deps + built workspace deps
# hard-linked in), with no workspace: protocol left to resolve.

# ── Stage 1: prune a self-contained deploy of suibench for the confirmer ──────
FROM suibench-base AS deploy

WORKDIR /repo
# Root workspace manifest + lockfile + package manifests drive dependency
# resolution; copy them first for layer caching, then the sources. `.npmrc`
# carries `inject-workspace-packages=true` — required so `pnpm deploy` bundles the
# `workspace:*` core dep into the pruned output, and so the lockfile's recorded
# `injectWorkspacePackages: true` setting matches (else --frozen-lockfile aborts).
COPY .npmrc package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.base.json ./tsconfig.base.json
COPY core ./core
COPY suibench ./suibench

RUN pnpm install --frozen-lockfile
# Build the workspace deps (core) and suibench so the deploy carries compiled JS.
RUN pnpm --filter core build && pnpm --filter suibench build
# Prune a self-contained deploy of suibench into /out (deps + built core inlined).
RUN pnpm deploy --filter=suibench --prod /out

# ── Shared runtime scaffolding: non-root user + baked .move cache in its HOME ──
# ubuntu:24.04 already occupies uid 1000, so drop that user first. The Move
# framework cache lives in root's home; a non-root Move build git-clones the
# framework (which the --network none container can't), so copy it to the user's
# HOME. Both final targets share this.
FROM suibench-base AS runtime-base
WORKDIR /workspace
COPY suibench/entrypoint.sh ./entrypoint.sh
RUN set -eux; \
  userdel --remove ubuntu 2>/dev/null || true; \
  useradd --create-home --uid 1000 --shell /bin/bash suibench; \
  cp -a /root/.move /home/suibench/.move; \
  chown -R suibench:suibench /home/suibench/.move /workspace
ENV HOME=/home/suibench

# ── Target: confirmer (trusted) — localnet + SDK + runner bundle. Functionally
# the former suibench-auditor: keeps the full pruned deploy and strips only the
# dataset answer key. Eval-integrity: the `dataset` ships in the npm package
# (`files`) so the installed CLI resolves its default dataset path, but it is the
# answer key (per-entry `check.ts` oracle, reference `exploits/`, gold `patches/`);
# strip it at the IMAGE layer, not by dropping it from `files`. Nothing in-container
# reads it (host-side only).
FROM runtime-base AS confirmer
COPY --from=deploy /out /workspace/suibench
RUN rm -rf /workspace/suibench/dataset && chown -R suibench:suibench /workspace/suibench
ENV SUIBENCH_SDK_DIR=/workspace/suibench
USER suibench
ENTRYPOINT ["./entrypoint.sh"]

# ── Target: untrusted-runtime — toolchain + SDK ONLY, at the workspace root so
# exploit scripts resolve @mysten/sui wherever the agent works. NO harness dist/,
# NO dataset, NO inlined `core` kernel. This image runs untrusted model code
# (authoring sandbox now; phase container in Plan 2), so its cleanliness is a
# tested isolation invariant (§9.1 invariant 4).
FROM runtime-base AS untrusted-runtime
# Install the two required tools directly instead of copying SuiBench's
# dependency graph. Exact top-level versions keep deliberate SDK/tool changes
# visible; the built image ID records the complete resolved graph used by a run.
# "type":"module" is required because the phase runs runner.ts (top-level await)
# from /workspace — without it tsx resolves runner.ts as CommonJS and it fails.
RUN printf '%s\n' '{"private":true,"type":"module","packageManager":"pnpm@10.33.0"}' \
    > /workspace/package.json \
  && pnpm --dir /workspace add --prod --save-exact --no-lockfile \
    @mysten/sui@2.22.0 \
    tsx@4.23.1 \
  && chown -R suibench:suibench /workspace
# Phase role entrypoint (Plan 2): copied as root at build time, no gosu/chown at
# runtime needed — the phase container overrides only --entrypoint at `docker
# create`, still running as this image's final USER suibench (uid 1000).
COPY --chmod=755 suibench/scripts/phase-entry.sh /usr/local/bin/phase-entry.sh
ENV SUIBENCH_SDK_DIR=/workspace
ENV NODE_PATH=/workspace/node_modules
USER suibench
ENTRYPOINT ["./entrypoint.sh"]
