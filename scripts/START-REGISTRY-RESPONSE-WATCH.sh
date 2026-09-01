#!/usr/bin/env bash
# Starts the HPAY registry response watch: the small program that answers an
# arbitration challenge on a registry channel for somebody who is not awake.
#
# It builds the binary, prints what it will and will not protect for your exact
# channel, and then polls. It never contacts a Hub - if it needed one it would
# be useless in the exact case it exists for.
#
# Production packaging: scripts/hpay-registry-response-watch/
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
NODE_URL="${HACASH_NODE_URL:-http://127.0.0.1:8080}"
POLL_INTERVAL="${HPAY_RESPONSE_WATCH_POLL_SECONDS:-60}"

cat <<'BANNER'

###########################################################################
#                                                                         #
#   THIS PROTECTS NOTHING WHILE IT IS NOT RUNNING                         #
#                                                                         #
###########################################################################

  The registry response watch answers an arbitration challenge before its
  window closes. The window is a fixed number of blocks. There is no queue
  and no catch-up: a challenge that opens and expires while this process is
  stopped is simply lost, and whatever bill the challenger named is what
  gets paid.

  So this is not a guarantee. It is a best-effort stand-in for a person who
  is asleep, and the size of the gap is printed below in minutes, computed
  from your own channel's challenge window rather than asserted.

  What it CAN do:
    answer a challenge that names a bill older than yours,
    finalise a close somebody else already started,
    send the settled money to your own address and nowhere else.

  What it CANNOT do, by construction:
    start a close - there is no challenge step in the program at all,
    pay itself or anyone but you - the contract pins the destination,
    touch any key of yours - it has only its own fee-paying key,
    renew your channel's storage lease - that is a different clock, and it
      is the one that destroys money outright. Renew it from the wallet.

  The one mistake that costs you is a STALE KIT. Export a fresh one after
  every payment. Answering with a bill older than your real head installs
  an older split, and an older split is the one the provider prefers.

###########################################################################

BANNER

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not found in PATH. Install the Rust toolchain first." >&2
  exit 1
fi

if [[ -z "${HPAY_RESPONSE_WATCH_KIT:-}" ]]; then
  cat <<'MISSING' >&2
ERROR: HPAY_RESPONSE_WATCH_KIT is not set.

  The exit kit is the file the wallet exports: your channel's binding plus
  the latest bill both you and the provider signed. It is not a private key
  and it cannot send your money anywhere but to you.

    export HPAY_RESPONSE_WATCH_KIT=/path/to/exit-kit.json

MISSING
  exit 1
fi
if [[ ! -r "${HPAY_RESPONSE_WATCH_KIT}" ]]; then
  echo "ERROR: cannot read the exit kit at ${HPAY_RESPONSE_WATCH_KIT}" >&2
  exit 1
fi
if [[ -z "${HPAY_RESPONSE_WATCH_SECRET_HEX:-}" ]]; then
  cat <<'MISSING' >&2
ERROR: HPAY_RESPONSE_WATCH_SECRET_HEX is not set.

  This is the responder's OWN key, and it does exactly one thing: pay the
  network fee for transactions the contract already lets anybody send. It
  must not be your wallet key, and it needs only enough HAC for three fees.

    export HPAY_RESPONSE_WATCH_SECRET_HEX=...

MISSING
  exit 1
fi

echo "[1/3] Building the response watch..."
cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p l2-fast-pay-hub --features registry-response-watch \
  --bin hpay-registry-response-watch

WATCH_BIN="${REPO_ROOT}/target/debug/hpay-registry-response-watch"
if [[ ! -x "${WATCH_BIN}" ]]; then
  echo "ERROR: ${WATCH_BIN} was not produced by the build." >&2
  exit 1
fi

echo "[2/3] Checking the fullnode at ${NODE_URL} once, without signing anything..."
# `--dry-run` reaches the identical decision the live loop would and submits
# nothing. If this cannot read the chain, neither can the loop, and finding
# that out before the banner is better than finding it out during a challenge.
if ! "${WATCH_BIN}" \
  --kit "${HPAY_RESPONSE_WATCH_KIT}" \
  --node-url "${NODE_URL}" \
  once --dry-run >/dev/null; then
  echo >&2
  echo "ERROR: the dry run could not complete. The loop would be blind." >&2
  echo "       Check that ${NODE_URL} is a synchronized HPAY-capable fullnode" >&2
  echo "       and that the kit names a channel that exists on it." >&2
  exit 1
fi
echo "      The fullnode answered and the kit matches a live channel."

echo "[3/3] Watching every ${POLL_INTERVAL}s. Ctrl-C stops it, and stopping it"
echo "      stops the protection. Nothing is queued while it is down."
echo
exec "${WATCH_BIN}" \
  --kit "${HPAY_RESPONSE_WATCH_KIT}" \
  --node-url "${NODE_URL}" \
  watch --poll-interval-seconds "${POLL_INTERVAL}"
