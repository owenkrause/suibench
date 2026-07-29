#!/usr/bin/env bash
set -euo pipefail

TARGET_CONTRACT="${TARGET_CONTRACT:?TARGET_CONTRACT env var must be set}"
NETWORK="${NETWORK:-devnet}"
# Seconds to wait for the localnet RPC / faucet before giving up. Bumped from 60
# to 180 because under host CPU contention (many localnets booting at once) a
# single validator's first-checkpoint production can exceed 60s — the old hard
# cap turned a transient slow boot into a hard failure. Override if needed.
READY_TIMEOUT="${SUI_BOOT_READY_TIMEOUT_SECS:-180}"

# ── Mainnet mode: no devnet, no deploy, just write context and go ──
if [ "$NETWORK" = "mainnet" ]; then
  PACKAGE_ID="${PACKAGE_ID:?PACKAGE_ID env var must be set for mainnet}"
  RPC_URL="https://fullnode.mainnet.sui.io:443"

  cat > /workspace/context.json <<CONTEXT
{
  "rpcUrl": "$RPC_URL",
  "packageId": "$PACKAGE_ID",
  "network": "mainnet"
}
CONTEXT

  echo "=== Container ready (mainnet dry-run) ==="
  touch /workspace/.ready
  exec tail -f /dev/null
fi

# The target is mounted :ro (a non-root UID can't write a host-owned mount);
# copy it to a writable /workspace/target to build (test-publish writes build/).
if [ -d /workspace/target-ro ]; then
  rm -rf /workspace/target
  cp -a /workspace/target-ro /workspace/target
fi

# ── Devnet mode: boot local network (supervised), deploy contract ──
# `sui start --with-faucet --force-regenesis` has an intermittent startup race.
# The in-process faucet runs a single, un-retried check for the genesis funding
# account's gas coins (sui-faucet `find_gas_coins_and_address`). That check fires
# a few ms after the cluster starts and races the fullnode indexing the genesis
# coin objects. When it loses, the faucet errors "No address found with sufficient
# coins"; because the faucet is built with `?` BEFORE the node health loop, that
# error terminates the ENTIRE `sui start` process in ~2s — not just the faucet
# (so the failure can surface as either RPC-never-ready or faucet-never-ready).
# Host CPU contention widens the window, so concurrent boots fail more often
# (observed ~40-60% single-boot failure under load). The failure is transient and
# self-terminating, so we supervise the boot and relaunch until RPC + faucet are
# both up. Overridable cap via SUI_BOOT_MAX_ATTEMPTS (failed attempts cost ~2s).
echo "=== Starting Sui devnet ==="
MAX_ATTEMPTS="${SUI_BOOT_MAX_ATTEMPTS:-20}"

rpc_ready() {
  curl -s -X POST http://127.0.0.1:9000 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sui_getLatestCheckpointSequenceNumber","id":1}' \
    2>/dev/null | grep -q '"result"'
}
faucet_ready() {
  case "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9123 2>/dev/null)" in
    200|404|405) return 0 ;;
    *) return 1 ;;
  esac
}

SUI_PID=""
booted=0
attempt=0
while [ "$attempt" -lt "$MAX_ATTEMPTS" ]; do
  attempt=$((attempt + 1))
  RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis &
  SUI_PID=$!
  echo "Boot attempt ${attempt}/${MAX_ATTEMPTS} (pid ${SUI_PID}); waiting up to ${READY_TIMEOUT}s for RPC + faucet..."
  for i in $(seq 1 "$READY_TIMEOUT"); do
    # The faucet race self-terminates the whole process in ~2s. Detect that
    # immediately instead of waiting out the full timeout on a dead process.
    if ! kill -0 "$SUI_PID" 2>/dev/null; then
      wait "$SUI_PID" 2>/dev/null || true
      echo "  attempt ${attempt} exited during boot (faucet genesis-coin race) — retrying" >&2
      break
    fi
    if faucet_ready && rpc_ready; then
      echo "RPC + faucet ready after ${i}s on attempt ${attempt}"
      booted=1
      break
    fi
    sleep 1
  done
  if [ "$booted" -eq 1 ]; then
    break
  fi
  # Timed out but still alive (rare slow/hung boot): kill and retry.
  if kill -0 "$SUI_PID" 2>/dev/null; then
    echo "  attempt ${attempt} not ready within ${READY_TIMEOUT}s; killing pid ${SUI_PID} and retrying" >&2
    kill "$SUI_PID" 2>/dev/null || true
    wait "$SUI_PID" 2>/dev/null || true
  fi
  sleep 1
done

if [ "$booted" -ne 1 ]; then
  echo "ERROR: Sui localnet failed to boot after ${MAX_ATTEMPTS} attempts" >&2
  exit 1
fi

# Configure client: create local env and switch to it
echo "Configuring Sui client..."
sui client new-env --alias local --rpc http://127.0.0.1:9000 -y 2>/dev/null || true
sui client switch --env local

# Generate keypairs using --json for reliable parsing
echo "=== Generating accounts ==="
ADMIN_ADDRESS=$(sui client new-address ed25519 admin --json | jq -r '.address')
ATTACKER_ADDRESS=$(sui client new-address ed25519 attacker --json | jq -r '.address')
USER_ADDRESS=$(sui client new-address ed25519 user --json | jq -r '.address')

echo "Admin:    $ADMIN_ADDRESS"
echo "Attacker: $ATTACKER_ADDRESS"
echo "User:     $USER_ADDRESS"

# Fund accounts via CLI faucet command
echo "=== Funding accounts ==="
for ADDR in "$ADMIN_ADDRESS" "$ATTACKER_ADDRESS" "$USER_ADDRESS"; do
  sui client faucet --address "$ADDR" --url http://127.0.0.1:9123/v2/gas 2>/dev/null || true
  echo "Funded $ADDR"
done

# Wait for faucet transactions to finalize
sleep 3

# Publish contract using test-publish for local/ephemeral environments
echo "=== Publishing contract: $TARGET_CONTRACT ==="
sui client switch --address "$ADMIN_ADDRESS" 2>/dev/null

PUBLISH_OUTPUT=$(sui client test-publish "/workspace/${TARGET_CONTRACT}" \
  --skip-dependency-verification \
  --publish-unpublished-deps \
  --gas-budget 500000000 \
  --build-env testnet \
  --json 2>&1) || true

# test-publish --json prefixes build progress lines before the JSON object;
# strip everything before the first '{' then extract packageId with jq
PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | sed -n '/^{/,$p' | jq -r '.objectChanges[] | select(.type == "published") | .packageId')

if [ -z "$PACKAGE_ID" ]; then
  echo "ERROR: Failed to extract package ID from publish output" >&2
  echo "$PUBLISH_OUTPUT" >&2
  exit 1
fi

echo "Package ID: $PACKAGE_ID"

# Export private keys using --json for reliable parsing
ADMIN_KEY=$(sui keytool export --key-identity admin --json | jq -r '.exportedPrivateKey')
ATTACKER_KEY=$(sui keytool export --key-identity attacker --json | jq -r '.exportedPrivateKey')
USER_KEY=$(sui keytool export --key-identity user --json | jq -r '.exportedPrivateKey')

# Write context
cat > /workspace/context.json <<CONTEXT
{
  "rpcUrl": "http://127.0.0.1:9000",
  "faucetUrl": "http://127.0.0.1:9123",
  "packageId": "$PACKAGE_ID",
  "adminAddress": "$ADMIN_ADDRESS",
  "attackerAddress": "$ATTACKER_ADDRESS",
  "userAddress": "$USER_ADDRESS",
  "adminKeyPair": "$ADMIN_KEY",
  "attackerKeyPair": "$ATTACKER_KEY",
  "userKeyPair": "$USER_KEY"
}
CONTEXT

echo "=== Container ready ==="
touch /workspace/.ready

# Keep container alive
exec tail -f /dev/null
