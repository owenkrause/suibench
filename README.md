# suibench

An execution-graded benchmark for finding and weaponizing real vulnerabilities in Sui move packages. The model is deployed into a docker container with the vulnerable package deployed on a localnet where it hypothesizes and executes transactions. suibench grades each finding by running the model's exploit on a fresh devnet localnet, then reading the resulting on-chain state. A finding is credited to a vulnerability through counterfactual attribution.

See [`DESIGN.md`](./DESIGN.md) for the full integrity architecture.

## Layout

This is a pnpm workspace with two packages:

- **`core/`** — the pure kernel: scoring, counterfactual attribution, the agent runtime, and the port interfaces (`Grader`, `Sandbox`, `Store`, `Judge`). No I/O, no Docker.
- **`suibench/`** — the benchmark: effectful adapters (the devnet confirmer, sandbox, model clients), the CLI, and the labeled `dataset/`.

## Dataset

`suibench/dataset/` holds labeled vulnerability entries in two tiers:

- **Confirmed-tier** (has `check.ts`) — graded deterministically by on-chain execution + counterfactual attribution against a gold patch.
- **Detect-tier** (no `check.ts`) — graded by an LLM judge over findings ↔ labels (for vulns without a snapshot-observable oracle).

Each entry contains `sources/` (the vulnerable Move package), `entry.json` (labels), `check.ts` (the snapshot-pure oracle), `exploits/` (a reference exploit), `patches/` (a gold patch per label), `harness/` (trusted setup/victim scripts), and `SOURCE.md` (provenance/attribution).

## Requirements

- Node ≥ 20, `pnpm`
- Docker (the confirmer boots a Sui devnet localnet per entry)
- An `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY` / `GEMINI_API_KEY`) for live model runs

## Quickstart

```bash
pnpm install
pnpm -r build

# Build the toolchain images (Sui CLI + prover stack, then the auditor image)
docker build -f suibench/Dockerfile.base -t suibench-base suibench      # once (heavy)
docker build -f suibench/Dockerfile      -t suibench-auditor suibench   # per code change

# Run the exploitation eval over the confirmed-tier corpus
ANTHROPIC_API_KEY=... node --import tsx suibench/src/bench/cli.ts \
  --dataset ./suibench/dataset --axis exploitation --harness harnessed \
  --model claude-opus-4-8 --effort medium --concurrency 5 --output ./run

# Integrity gates (Docker, no model)
pnpm --filter suibench verify:graders   # every reference exploit confirms with perfect attribution
pnpm --filter suibench verify:twins     # perturbation twins grade identically to their originals
```

## License

tbd. Dataset entries adapted from public protocol code retain their original attribution in each entry's `SOURCE.md`.
