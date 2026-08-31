#!/usr/bin/env bash
# Runs as the image's UNPRIVILEGED user (uid 1000) under --cap-drop=ALL — no root, no
# gosu, no chown. The docker-cp'd payload lands world-readable and the runner only
# READS it; the one thing needing write is the target (sui move build emits build/,
# helpers rewrite Move.toml), so copy it into a dir this user owns. `exec` makes node
# PID 1 — the boundary is its exit.
#
# NOT `node_modules/.bin/tsx runner.ts` — that shell-script bin forks a CHILD node
# (so `process.pid` inside the runner isn't 1, breaking the PID-1 boundary).
# `node --import tsx` registers tsx as a loader hook IN this process instead, so
# this exec'd node itself becomes the runner.
set -euo pipefail
[ -d /workspace/target-src ] && cp -r /workspace/target-src /workspace/target
cd /workspace
exec node --import tsx runner.ts "${ATTACK_SCRIPT}" attack
