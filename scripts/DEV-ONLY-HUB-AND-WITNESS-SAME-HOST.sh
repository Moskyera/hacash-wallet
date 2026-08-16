#!/usr/bin/env bash
# Local development only. Starts the Fast Pay Hub and a rollback-anchor witness
# together on this one machine.
#
# This is the configuration ADR-001 calls Option B, and Option B defends against
# nothing. It exists because local development and the Local Pilot need a witness
# to talk to, not because it makes anything safer.
#
# Production:  scripts/START-HUB-WITH-REMOTE-WITNESS.sh
# Real witness operator guide: docs/l2/RUNNING-A-WITNESS.md
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DEV_DIR="${REPO_ROOT}/.dev-anchor"
WITNESS_LISTEN="127.0.0.1:8791"
WITNESS_URL="http://127.0.0.1:8791"
HUB_LISTEN="127.0.0.1:8790"
NODE_URL="${HACASH_NODE_URL:-http://127.0.0.1:8080}"
WITNESS_ID="dev-local-witness"
STORE_FILE="${DEV_DIR}/witness-store.log"
ATTESTATION_FILE="${DEV_DIR}/dev-attestation.json"
ATTEST_LOG="${DEV_DIR}/dev-attestation.stderr"
HUB_STATE_FILE="${DEV_DIR}/dev-hub-state.json"

# Well-known, worthless development keys. They are written down in a script in a
# public repository on purpose: nothing that uses them may ever hold value.
WITNESS_RECEIPT_SECRET="hpay-dev-witness-receipt-key-do-not-use-anywhere-real"
WITNESS_AUTHORISATION_SECRET="hpay-dev-witness-authorisation-key-do-not-use-anywhere-real"

cat <<'BANNER'

###########################################################################
#                                                                         #
#   DEVELOPMENT CONFIGURATION - THE ROLLBACK ANCHOR DOES NOT COUNT HERE   #
#                                                                         #
###########################################################################

  The witness you are about to start runs on THIS machine, writes its
  counter to THIS filesystem, and is in THIS machine's backup set.

  That means it goes backwards exactly when the Hub goes backwards.
  Restore this box from an image taken an hour ago and the Hub's state and
  the witness's counter both come back at the older position, agreeing with
  each other perfectly. Every signature verifies. Every check passes. The
  Hub will happily co-sign a bill serial it has already co-signed, with
  different balances, and nothing in this configuration will notice.

  That is the entire failure the anchor exists to prevent, and this
  configuration does not prevent it. ADR-001 calls this Option B and
  rejected it. It is here because local development needs a witness to talk
  to, and for no other reason.

  What you DO get here: the wire protocol, the receipts, the refusals, the
  startup probe and the recovery drills, all real and all exercisable.
  What you DO NOT get: an anchor.

  The Hub will publish this honestly. In the rollback_anchor object on
  /v1/readiness/mainnet you will see
    witness_endpoint_posture        : same_host_or_plaintext
    witness_endpoint_is_local       : true
    witness_store_in_hub_state_tree : true
    witness_co_located              : true
    witness_operator                : LOCAL-DEV-NO-SEPARATION
  On a mainnet profile the Hub refuses to start in this shape at all. It
  starts here only because this is the development profile. If you ever see
  that operator string, or witness_co_located true, on a machine holding
  real value, that Hub has no anchor and somebody needs to be told today.

  Real deployment:     docs/l2/RUNNING-A-WITNESS.md
  Production launcher: scripts/START-HUB-WITH-REMOTE-WITNESS.sh

###########################################################################

BANNER

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not found in PATH. Install the Rust toolchain first." >&2
  exit 1
fi

if [[ -z "${HACASH_HUB_ADDRESS:-}" ]]; then
  cat <<'MISSING' >&2
ERROR: HACASH_HUB_ADDRESS is not set.

  The witness's deployment attestation is bound to one exact Hub identity,
  so the Hub address has to be known before anything starts.

    export HACASH_HUB_ADDRESS=1YourDevHubAddress
    export HACASH_HUB_SECRET_HEX=your64characterdevprivatekey

MISSING
  exit 1
fi
if [[ -z "${HACASH_HUB_SECRET_HEX:-}" ]]; then
  echo "ERROR: HACASH_HUB_SECRET_HEX is not set. The rollback anchor binds the key" >&2
  echo "       that signs bills, so the Hub needs its signer before the anchor" >&2
  echo "       can be attached." >&2
  exit 1
fi

mkdir -p "${DEV_DIR}"

echo "[1/6] Building the Hub and the witness..."
cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" \
  -p l2-fast-pay-hub --features rollback-witness \
  --bin fast-pay-hub --bin hpay-rollback-witness

WITNESS_BIN="${REPO_ROOT}/target/debug/hpay-rollback-witness"
HUB_BIN="${REPO_ROOT}/target/debug/fast-pay-hub"
for binary in "${WITNESS_BIN}" "${HUB_BIN}"; do
  if [[ ! -x "${binary}" ]]; then
    echo "ERROR: ${binary} was not produced by the build." >&2
    exit 1
  fi
done

echo "[2/6] Reading the witness store identity..."
INSTANCE_OUTPUT="$("${WITNESS_BIN}" \
  --witness-id "${WITNESS_ID}" \
  --store "${STORE_FILE}" \
  --receipt-secret-hex "${WITNESS_RECEIPT_SECRET}" \
  instance)"
WITNESS_RECEIPT_ADDRESS="$(printf '%s\n' "${INSTANCE_OUTPUT}" | sed -n 's/^witness_receipt_address=//p')"
WITNESS_INSTANCE_ID="$(printf '%s\n' "${INSTANCE_OUTPUT}" | sed -n 's/^witness_instance_id=//p')"
if [[ -z "${WITNESS_RECEIPT_ADDRESS}" || -z "${WITNESS_INSTANCE_ID}" ]]; then
  echo "ERROR: the witness would not report its store identity." >&2
  printf '%s\n' "${INSTANCE_OUTPUT}" >&2
  exit 1
fi
echo "      witness_instance_id     = ${WITNESS_INSTANCE_ID}"
echo "      witness_receipt_address = ${WITNESS_RECEIPT_ADDRESS}"

echo "[3/6] Issuing a one-day development attestation..."
# The posture enum has no "same host" value, on purpose: a configuration that
# wants it cannot express it. So the separation statement carries the truth, and
# it is written to be read out loud during an incident. One day of validity, so
# this cannot be set once and forgotten.
"${WITNESS_BIN}" \
  --witness-id "${WITNESS_ID}" \
  --store "${STORE_FILE}" \
  --receipt-secret-hex "${WITNESS_RECEIPT_SECRET}" \
  attest \
  --hub-identity "${HACASH_HUB_ADDRESS}" \
  --authorisation-secret-hex "${WITNESS_AUTHORISATION_SECRET}" \
  --posture same-operator-separate-infrastructure \
  --witness-operator "LOCAL-DEV-NO-SEPARATION" \
  --separation-statement "NONE. This witness runs on the same host, the same filesystem and the same backup set as the Hub state it witnesses. There is no separation of any kind. This is ADR-001 Option B and it defends against nothing. Local development only." \
  --validity-days 1 \
  > "${ATTESTATION_FILE}" 2> "${ATTEST_LOG}"

WITNESS_AUTHORISATION_ADDRESS="$(sed -n 's/^witness_authorisation_address=//p' "${ATTEST_LOG}")"
if [[ -z "${WITNESS_AUTHORISATION_ADDRESS}" ]]; then
  echo "ERROR: the attestation did not report the authorisation address." >&2
  cat "${ATTEST_LOG}" >&2
  exit 1
fi
echo "      witness_authorisation_address = ${WITNESS_AUTHORISATION_ADDRESS}"

echo "[4/6] Starting the witness on ${WITNESS_LISTEN} ..."
"${WITNESS_BIN}" \
  --witness-id "${WITNESS_ID}" \
  --store "${STORE_FILE}" \
  --receipt-secret-hex "${WITNESS_RECEIPT_SECRET}" \
  serve --listen "${WITNESS_LISTEN}" &
WITNESS_PID=$!

stop_witness() {
  if kill -0 "${WITNESS_PID}" 2>/dev/null; then
    echo
    echo "Stopping the development witness (pid ${WITNESS_PID})..."
    kill "${WITNESS_PID}" 2>/dev/null || true
    wait "${WITNESS_PID}" 2>/dev/null || true
  fi
}
trap stop_witness EXIT INT TERM

echo "[5/6] Waiting for the witness to accept connections (max 30s)..."
witness_up=0
for _ in $(seq 1 30); do
  # The connection is opened and closed inside a subshell, so nothing is left
  # holding a socket against the witness.
  if (exec 3<>/dev/tcp/127.0.0.1/8791) 2>/dev/null; then
    witness_up=1
    break
  fi
  if ! kill -0 "${WITNESS_PID}" 2>/dev/null; then
    echo "ERROR: the witness exited before it started listening." >&2
    exit 1
  fi
  sleep 1
done
if [[ "${witness_up}" -ne 1 ]]; then
  echo "ERROR: the witness did not start listening within 30 seconds." >&2
  exit 1
fi
echo "      Witness is listening."

cat <<EOF
[6/6] Starting the Hub on ${HUB_LISTEN} pointing at ${WITNESS_URL} ...

  Reminder, because this is the moment it matters: the anchor does not count
  in this configuration. The witness is on this same host, in this same
  backup set. Restore this machine and both go backwards together.

  What the Hub says about its own anchor:
    curl http://${HUB_LISTEN}/v1/readiness/mainnet
  Ctrl-C here stops the Hub and the witness together.

EOF

# Deliberately not `exec`: the EXIT trap above is what stops the witness when
# the Hub exits or you press Ctrl-C. Replacing this shell would orphan it.
"${HUB_BIN}" \
  --listen "${HUB_LISTEN}" \
  --node-url "${NODE_URL}" \
  --deployment-profile development \
  --hub-address "${HACASH_HUB_ADDRESS}" \
  --hub-secret-hex "${HACASH_HUB_SECRET_HEX}" \
  --state-file "${HUB_STATE_FILE}" \
  --rollback-witness-url "${WITNESS_URL}" \
  --rollback-witness-id "${WITNESS_ID}" \
  --rollback-witness-receipt-address "${WITNESS_RECEIPT_ADDRESS}" \
  --rollback-witness-authorisation-address "${WITNESS_AUTHORISATION_ADDRESS}" \
  --rollback-witness-attestation-file "${ATTESTATION_FILE}"
