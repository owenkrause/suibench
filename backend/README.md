# Benchmark grading server

A Node standalone server (Astro + `@astrojs/node`) that serves the SuiBench
dataset and grades findings submissions. It **must run on a Docker-capable
host**: grading spawns Sui localnets in containers, so it can't run on a
serverless/edge platform.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/benchmark/manifest` | Dataset version + entry list (no ground truth). |
| `GET` | `/api/benchmark/dataset` | Download the full corpus as a `.tar.gz`. |
| `GET` | `/api/benchmark/dataset/:id` | Download a single entry. |
| `POST` | `/api/benchmark/submissions` | Submit findings; returns a submission id. |
| `GET` | `/api/benchmark/submissions/:id` | Poll status → metrics + per-finding correctness (the ground-truth labels stay redacted). |

## Requirements

- Node ≥ 22.13, pnpm 10
- Docker (grading runs the per-role images — see below)
- PostgreSQL (submission + score persistence; schema is created automatically on first submission)

## Environment

| Var | Required | Default | Meaning |
| --- | --- | --- | --- |
| `DATABASE_URL` | yes | — | Postgres connection string. |
| `BENCHMARK_GRADE_SLOTS` | no | `2` | Max concurrent grading jobs. |
| `BENCHMARK_MAX_INFLIGHT` | no | `100` | Cap on total in-flight submissions. |
| `HOST` / `PORT` | no | `0.0.0.0` / `4321` | Standard `@astrojs/node` standalone bind address. |

## Build & run

From the repo root:

```sh
pnpm install
pnpm --filter core build && pnpm --filter suibench build
pnpm --filter backend build
DATABASE_URL=postgres://user:pass@127.0.0.1:5432/bench \
  node backend/dist/server/entry.mjs
```

## Grading images

Grading runs untrusted model code, so each role has its own pre-built Docker
image (referenced by tag; override with `SUIBENCH_*_IMAGE` env vars). Build them
once from the repo root before grading — see `../suibench/Dockerfile`,
`../suibench/Dockerfile.base`, and `../suibench/Dockerfile.gate` for the exact
`docker build` commands.
