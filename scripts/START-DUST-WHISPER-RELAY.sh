#!/usr/bin/env bash
# Starts a DUST Whisper relay: the mailbox the wallet messenger collects from,
# and the encrypted submit path that forwards transactions to a fullnode.
# One parameter: the fullnode URL this relay forwards transactions to.
#
#   ./START-DUST-WHISPER-RELAY.sh https://nodeapi.example.org
#
# There is no default node URL here on purpose. A wallet compares the node this
# relay declares against its own node and refuses to broadcast through it if
# they differ, so a guessed default produces a relay that looks online and
# blocks every transaction. Chat still works in that state, which makes it
# harder to diagnose, not easier.
#
# Everything else is read from the environment:
#
#   DUST_WHISPER_LISTEN      host:port to bind         (default 127.0.0.1:8787)
#                            The desktop wallet auto-starts its own relay on
#                            that same port by default, so if the wallet is
#                            open here, this bind fails. Move one of the two.
#   DUST_WHISPER_KEY_FILE    relay X25519 secret key   (default ~/.hacash-dust-whisper/relay.key)
#   DUST_WHISPER_SECRET_HEX  the key itself, read by the binary; overrides the file
#   DUST_WHISPER_RELAY_BIN   path to the binary
#   RUST_LOG                 default info. debug logs recipient addresses.
#
# What running this means for the people who use it: docs/RUNNING-A-RELAY.md,
# section 6. Read it before you publish the address.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
NODE_URL="${1:-}"

if [[ -z "${NODE_URL}" ]]; then
  cat <<USAGE >&2
ERROR: no fullnode URL given.

  Usage: $(basename "$0") https://nodeapi.example.org

  The relay decrypts transactions submitted to it and posts them to one node
  that you choose. This script will not guess which. It has to be the same node
  the wallets using this relay are configured with, or their Privacy screen
  reports "Broadcast blocked" and nobody can tell why.

  Running a relay, and what you can see once you do: docs/RUNNING-A-RELAY.md

USAGE
  exit 1
fi

case "${NODE_URL}" in
  http://*|https://*) ;;
  *)
    echo "ERROR: node URL must start with http:// or https://, got ${NODE_URL}" >&2
    exit 1
    ;;
esac

LISTEN="${DUST_WHISPER_LISTEN:-127.0.0.1:8787}"
KEY_FILE="${DUST_WHISPER_KEY_FILE:-${HOME}/.hacash-dust-whisper/relay.key}"
export RUST_LOG="${RUST_LOG:-info}"

# Release first, because that is what the build command below produces. The
# .exe variants are for running this under git-bash on Windows.
RELAY_CANDIDATES=(
  "${REPO_ROOT}/target/release/dust-whisper-relay"
  "${REPO_ROOT}/target/release/dust-whisper-relay.exe"
  "${REPO_ROOT}/target/debug/dust-whisper-relay"
  "${REPO_ROOT}/target/debug/dust-whisper-relay.exe"
)

RELAY_BIN="${DUST_WHISPER_RELAY_BIN:-}"
if [[ -z "${RELAY_BIN}" ]]; then
  for candidate in "${RELAY_CANDIDATES[@]}"; do
    if [[ -x "${candidate}" ]]; then
      RELAY_BIN="${candidate}"
      break
    fi
  done
fi
if [[ -z "${RELAY_BIN}" || ! -x "${RELAY_BIN}" ]]; then
  {
    if [[ -n "${DUST_WHISPER_RELAY_BIN:-}" ]]; then
      echo "ERROR: relay binary not found at ${RELAY_BIN}"
      echo "       (from DUST_WHISPER_RELAY_BIN)"
    else
      # Naming one path here used to send people looking at a debug build
      # moments after being told to make a release one. List what was tried.
      echo "ERROR: no relay binary found. Looked for:"
      for candidate in "${RELAY_CANDIDATES[@]}"; do
        echo "         ${candidate}"
      done
      echo "       CARGO_TARGET_DIR moves these. Set DUST_WHISPER_RELAY_BIN if yours is elsewhere."
    fi
    cat <<'BUILD'

  Build it:
    cargo build -p dust-whisper --features relay --bin dust-whisper-relay --release --locked

  The relay feature is off in a default build, so plain 'cargo build' does not
  produce this binary.

BUILD
  } >&2
  exit 1
fi

mkdir -p "$(dirname -- "${KEY_FILE}")"
chmod 700 "$(dirname -- "${KEY_FILE}")" 2>/dev/null || true

KEY_STATE="existing key"
if [[ ! -f "${KEY_FILE}" && -z "${DUST_WHISPER_SECRET_HEX:-}" ]]; then
  KEY_STATE="none yet, one will be generated"
fi
if [[ -n "${DUST_WHISPER_SECRET_HEX:-}" ]]; then
  KEY_STATE="from DUST_WHISPER_SECRET_HEX, file ignored"
fi

LISTEN_HOST="${LISTEN%:*}"
PUBLIC_WARNING=""
case "${LISTEN_HOST}" in
  127.0.0.1|localhost|::1|"[::1]") ;;
  *)
    PUBLIC_WARNING="yes"
    ;;
esac

cat <<BANNER

========================================================================
 DUST Whisper relay
========================================================================

  Listen        : ${LISTEN}
  Forwards to   : ${NODE_URL}
  Key file      : ${KEY_FILE}
  Key           : ${KEY_STATE}
  RUST_LOG      : ${RUST_LOG}

  Two things this relay does, in one process. It holds encrypted chat
  envelopes until their recipient collects them, and it decrypts submitted
  transactions and posts them to the node above.

  What you will be able to see: both addresses and the timing of every
  message, because the envelope carries 'to' and 'from' in clear so the relay
  can route on one and check the sender's signature against the other. Sealed
  message bodies are closed to you. Bodies sent before the two wallets had
  each other's keys are not: their key is derived from the two addresses that
  are printed on the envelope. And you decrypt every transaction submitted
  through the transaction path in full.

  Undelivered mail is held in memory and nowhere else. Restarting this process
  drops it, and neither sender nor recipient is told.

  Running a relay means holding other people's metadata. docs/RUNNING-A-RELAY.md
  section 6 says exactly how much, and section 9 is the short list of things
  that turn a useful relay into a harmful one.

========================================================================

BANNER

if [[ -n "${PUBLIC_WARNING}" ]]; then
  cat <<PUBLIC

  NOTE: binding ${LISTEN}. That is not 127.0.0.1 or localhost, so treat
  this listener as reachable by other machines.

  Terminate HTTPS in a reverse proxy in front of this. The wallet enforces
  HTTPS for transactions to a non local relay, but the messenger path does
  not check the scheme at all, so a plain http:// relay URL carries chat
  across the network with both addresses readable by anyone on the path.

  Check your proxy access log before you publish the address: the inbox
  challenge carries the recipient address in the query string, so a default
  log records who collected mail and when, in a file this relay knows nothing
  about.

PUBLIC
fi

case "${RUST_LOG}" in
  *debug*|*trace*)
    cat <<LOGGING

  NOTE: RUST_LOG is ${RUST_LOG}. At debug the request tracing layer prints
  full URIs, and the inbox challenge URI contains a user's address. That log
  is a record of who checked their mail and when. Use info unless you are
  actively debugging, and delete what you collected afterwards.

LOGGING
    ;;
esac

exec "${RELAY_BIN}" \
  --listen "${LISTEN}" \
  --node-url "${NODE_URL}" \
  --key-file "${KEY_FILE}"
