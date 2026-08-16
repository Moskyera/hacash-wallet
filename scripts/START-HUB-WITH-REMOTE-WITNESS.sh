#!/usr/bin/env bash
# Starts the Fast Pay Hub pointing at a rollback-anchor witness that runs
# somewhere else. One parameter: the witness base URL.
#
#   ./START-HUB-WITH-REMOTE-WITNESS.sh https://witness.example.org
#
# Everything else the anchor needs is read from the environment, because the Hub
# binary already reads those variables itself:
#
#   HACASH_HUB_ROLLBACK_WITNESS_ID
#   HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS
#   HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS
#   HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE
#
# Moving to a different witness - your own, the counterparty's, a neutral third
# party's - is a change to the argument above and those four values. It is never
# a code change. See docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md and
# docs/l2/RUNNING-A-WITNESS.md.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
WITNESS_URL="${1:-}"

if [[ -z "${WITNESS_URL}" ]]; then
  cat <<USAGE >&2
ERROR: no witness URL given.

  Usage: $(basename "$0") https://witness.example.org

  There is no default witness address, and this script will not invent one. A
  URL that does not answer is worse than an empty field: the Hub would refuse to
  sign for a reason nobody could explain. Pick a witness and pass it.

  Running one yourself: docs/l2/RUNNING-A-WITNESS.md

USAGE
  exit 1
fi

missing=()
for variable in \
  HACASH_HUB_ROLLBACK_WITNESS_ID \
  HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS \
  HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS \
  HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE
do
  if [[ -z "${!variable:-}" ]]; then
    missing+=("${variable}")
  fi
done
if (( ${#missing[@]} > 0 )); then
  cat <<INCOMPLETE >&2
ERROR: the anchor configuration is incomplete. Missing: ${missing[*]}

  All five anchor settings are required together. A partial anchor
  configuration is refused rather than run without an anchor, because a Hub
  that was meant to have one and silently does not is the worst outcome
  available.

  The witness operator gives you all four values plus the URL. See
  docs/l2/RUNNING-A-WITNESS.md, "Pointing a Hub at it".

INCOMPLETE
  exit 1
fi

if [[ ! -r "${HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE}" ]]; then
  cat <<ATTESTATION >&2
ERROR: attestation file not readable:
  ${HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE}

  It is the signed statement naming who runs the witness and what separates its
  failure domain from this Hub's. It has a bounded life on purpose; if it has
  expired, ask the witness operator to sign a fresh one. Do not relax the check.

ATTESTATION
  exit 1
fi

if [[ -z "${HACASH_HUB_ADDRESS:-}" ]]; then
  echo "ERROR: HACASH_HUB_ADDRESS is not set. See docs/HUB-OPERATOR.md." >&2
  exit 1
fi
if [[ -z "${HACASH_HUB_SECRET_HEX:-}" ]]; then
  echo "ERROR: HACASH_HUB_SECRET_HEX is not set. The rollback anchor binds the key" >&2
  echo "       that signs bills, so the Hub needs its signer." >&2
  exit 1
fi

HUB_BIN="${HPAY_HUB_BIN:-}"
if [[ -z "${HUB_BIN}" ]]; then
  if [[ -x "/opt/hpay-fast-pay-hub/fast-pay-hub" ]]; then
    HUB_BIN="/opt/hpay-fast-pay-hub/fast-pay-hub"
  elif [[ -x "${REPO_ROOT}/target/release/fast-pay-hub" ]]; then
    HUB_BIN="${REPO_ROOT}/target/release/fast-pay-hub"
  else
    HUB_BIN="${REPO_ROOT}/target/debug/fast-pay-hub"
  fi
fi
if [[ ! -x "${HUB_BIN}" ]]; then
  echo "ERROR: Hub binary not found at ${HUB_BIN}" >&2
  echo "  Build it:" >&2
  echo "    cargo build -p l2-fast-pay-hub --features server --bin fast-pay-hub --release --locked" >&2
  exit 1
fi

HUB_LISTEN="${HACASH_HUB_LISTEN:-127.0.0.1:8790}"
NODE_URL="${HACASH_NODE_URL:-http://127.0.0.1:8080}"
PROFILE="${HACASH_HUB_DEPLOYMENT_PROFILE:-mainnet-bounded-pilot}"

state_args=()
if [[ -n "${HACASH_HUB_STATE_FILE:-}" ]]; then
  state_args=(--state-file "${HACASH_HUB_STATE_FILE}")
fi

cat <<BANNER

========================================================================
 HPAY Fast Pay Hub with an external rollback anchor
========================================================================

  Witness URL   : ${WITNESS_URL}
  Witness id    : ${HACASH_HUB_ROLLBACK_WITNESS_ID}
  Attestation   : ${HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE}
  Hub listen    : ${HUB_LISTEN}
  Node API      : ${NODE_URL}
  Profile       : ${PROFILE}

  The Hub reserves its exact ledger position with that witness before it uses
  its signing key. If the witness is unreachable, the Hub refuses to sign and
  the channels freeze. That is the designed behaviour and there is no flag that
  changes it. Frozen channels lose nobody any money.

  If the witness is run by the same organisation that runs this Hub, read
  ADR-001 on what that does and does not protect against before telling anybody
  this Hub is anchored.

========================================================================

BANNER

exec "${HUB_BIN}" \
  --listen "${HUB_LISTEN}" \
  --node-url "${NODE_URL}" \
  --deployment-profile "${PROFILE}" \
  --hub-fee-mei 0 \
  "${state_args[@]}" \
  --rollback-witness-url "${WITNESS_URL}"
