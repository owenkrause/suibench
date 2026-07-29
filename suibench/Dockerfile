# suibench-auditor: the eval/confirmer image. Fast to build on top of the heavy
# base toolchain (Sui CLI + Node + pnpm + baked Move framework cache):
#   docker build -f suibench/Dockerfile.base -t suibench-base .     (once)
#   docker build -f suibench/Dockerfile      -t suibench-auditor .  (per code change)
#
# BUILD CONTEXT IS THE WORKSPACE ROOT (research/sui-sec), not suibench/ — the
# pnpm workspace + root lockfile must be visible so we can prune a self-contained
# deploy for suibench.
#
# Why not the legacy `COPY package.json pnpm-lock.yaml && pnpm install
# --frozen-lockfile`? Under the pnpm workspace there is no package-local lockfile
# (the lock lives at the workspace root and covers all four packages), so that
# recipe can't resolve suibench's deps in isolation. `pnpm deploy` solves exactly
# this: it produces a PRUNED, self-contained node_modules for one workspace
# package (its runtime deps + built workspace deps hard-linked in), with no
# workspace: protocol left to resolve. The container only needs @mysten/sui + tsx
# at runtime (to run the in-container confirmer runner under `npx tsx`).

# ── Stage 1: prune a self-contained deploy of suibench from the workspace ──
FROM suibench-base AS deploy

WORKDIR /repo
# Root workspace manifest + lockfile + package manifests drive dependency
# resolution; copy them first for layer caching, then the sources. `.npmrc`
# carries `inject-workspace-packages=true` — required so `pnpm deploy` bundles the
# `workspace:*` core dep into the pruned output, and so the lockfile's recorded
# `injectWorkspacePackages: true` setting matches (else --frozen-lockfile aborts).
COPY .npmrc package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY core ./core
COPY suibench ./suibench

RUN pnpm install --frozen-lockfile
# Build the workspace deps (core) and suibench so the deploy carries compiled JS.
RUN pnpm --filter core build && pnpm --filter suibench build
# Prune a self-contained deploy of suibench into /out (deps + built core inlined).
RUN pnpm deploy --filter=suibench --prod /out

# ── Stage 2: the runtime image the confirmer boots ──
FROM suibench-base

WORKDIR /workspace

# The pruned, self-contained suibench (node_modules + compiled dist) — no install,
# no lockfile resolution at image-build time beyond stage 1.
COPY --from=deploy /out /workspace/suibench

COPY suibench/entrypoint.sh ./entrypoint.sh

# Run the untrusted workload as an unprivileged user, not root. The baked Move
# framework cache lives in root's home (/root/.move); copy it to the user's HOME
# or a non-root boot git-clones the framework instead of reusing it. ubuntu:24.04
# already occupies UID 1000, so drop that user first.
RUN set -eux; \
  userdel --remove ubuntu 2>/dev/null || true; \
  useradd --create-home --uid 1000 --shell /bin/bash suibench; \
  cp -a /root/.move /home/suibench/.move; \
  chown -R suibench:suibench /home/suibench/.move /workspace

ENV HOME=/home/suibench
USER suibench

ENTRYPOINT ["./entrypoint.sh"]
