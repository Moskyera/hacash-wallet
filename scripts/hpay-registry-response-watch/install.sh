#!/usr/bin/env bash
# Installs the HPAY registry response watch as a locked-down systemd service.
#
# Keep install.sh, hpay-registry-response-watch.service, README.md and the
# built hpay-registry-response-watch binary in the same directory, then run
# this as root.
#
# It refuses rather than guesses: a poll interval that could step over a whole
# challenge window, a fee-paying key that is missing, or an exit kit the binary
# will not verify all stop the install. A watch installed in a shape that
# cannot answer is worse than no watch, because somebody will believe in it.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run this as root." >&2
  exit 1
fi

SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_NAME="hpay-registry-response-watch"
SERVICE_NAME="hpay-registry-response-watch"
OPT_DIR="/opt/${SERVICE_NAME}"
ETC_DIR="/etc/${SERVICE_NAME}"
VAR_DIR="/var/lib/${SERVICE_NAME}"
ENV_FILE="${ETC_DIR}/watch.env"
KIT_FILE="${ETC_DIR}/exit-kit.json"
SERVICE_USER="hpaywatch"

for required in "${BIN_NAME}" "${SERVICE_NAME}.service" "README.md"; do
  if [[ ! -f "${SRC_DIR}/${required}" ]]; then
    echo "ERROR: ${required} is not next to install.sh." >&2
    exit 1
  fi
done

if [[ -f "${ENV_FILE}" ]]; then
  cat >&2 <<EOF
ERROR: ${ENV_FILE} already exists.

  This installer will not overwrite an existing configuration or key. To
  upgrade, stop the service, replace only ${OPT_DIR}/${BIN_NAME}, and start it
  again. To change the kit, replace ${KIT_FILE} and restart.
EOF
  exit 1
fi

read -r -p "Path to the exit kit exported from the wallet: " KIT_SOURCE
if [[ ! -r "${KIT_SOURCE}" ]]; then
  echo "ERROR: cannot read ${KIT_SOURCE}" >&2
  exit 1
fi

read -r -p "Fullnode URL (NOT a Hub) [http://127.0.0.1:8080]: " NODE_URL
NODE_URL="${NODE_URL:-http://127.0.0.1:8080}"

read -r -p "Poll interval in seconds [60]: " POLL_INTERVAL
POLL_INTERVAL="${POLL_INTERVAL:-60}"

# The responder's own key. It pays network fees for steps the contract already
# lets anybody take, and it can move nothing else. It must not be the wallet
# key: a machine that is online all the time is not where a wallet key lives.
read -r -s -p "Responder fee-paying secret (NEVER your wallet key): " SECRET_HEX
echo
if [[ -z "${SECRET_HEX}" ]]; then
  echo "ERROR: the responder needs its own key to pay fees with." >&2
  exit 1
fi

echo
echo "Checking the kit and the interval before anything is installed..."
# `explain` verifies both signatures on the bill against the binding, prints
# the exact coverage, and reads no chain and no key. If the kit is not good
# the install stops here rather than after a service is running.
"${SRC_DIR}/${BIN_NAME}" --kit "${KIT_SOURCE}" --node-url "${NODE_URL}" \
  explain --poll-interval-seconds "${POLL_INTERVAL}"

CHALLENGE_BLOCKS="$(grep -o '"challenge_blocks"[[:space:]]*:[[:space:]]*[0-9]*' "${KIT_SOURCE}" | grep -o '[0-9]*$' | head -n 1)"
if [[ -z "${CHALLENGE_BLOCKS}" ]]; then
  echo "ERROR: the kit does not name a challenge window." >&2
  exit 1
fi
# The same arithmetic the binary enforces, applied before install so that a
# configuration that cannot protect anybody never gets as far as running.
USABLE_SECONDS=$(( (CHALLENGE_BLOCKS - 3) * 300 ))
if (( POLL_INTERVAL < 60 )) || (( POLL_INTERVAL > USABLE_SECONDS )); then
  cat >&2 <<EOF

ERROR: a ${POLL_INTERVAL}s poll interval cannot answer a ${CHALLENGE_BLOCKS}-block
       challenge window. The usable window is ${USABLE_SECONDS}s, so a challenge could
       open and expire between two looks. Choose an interval between 60s and
       ${USABLE_SECONDS}s.
EOF
  exit 1
fi

echo
read -r -p "Install with these settings? [y/N]: " CONFIRM
if [[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]]; then
  echo "Nothing was installed."
  exit 1
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -m 0755 "${OPT_DIR}"
install -d -m 0750 -o root -g "${SERVICE_USER}" "${ETC_DIR}"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${VAR_DIR}"

install -m 0755 "${SRC_DIR}/${BIN_NAME}" "${OPT_DIR}/${BIN_NAME}"
install -m 0644 "${SRC_DIR}/README.md" "${OPT_DIR}/README.md"
install -m 0640 -o root -g "${SERVICE_USER}" "${KIT_SOURCE}" "${KIT_FILE}"

umask 0077
cat > "${ENV_FILE}" <<EOF
HPAY_RESPONSE_WATCH_KIT=${KIT_FILE}
HPAY_RESPONSE_WATCH_NODE_URL=${NODE_URL}
HPAY_RESPONSE_WATCH_SECRET_HEX=${SECRET_HEX}
HPAY_RESPONSE_WATCH_POLL_SECONDS=${POLL_INTERVAL}
EOF
chown root:"${SERVICE_USER}" "${ENV_FILE}"
chmod 0640 "${ENV_FILE}"
unset SECRET_HEX

# The unit takes its whole configuration, poll interval included, from the
# environment file above. Nothing is templated into the unit, so replacing the
# kit or the interval is an edit to one file and a restart.
install -m 0644 "${SRC_DIR}/${SERVICE_NAME}.service" \
  "/etc/systemd/system/${SERVICE_NAME}.service"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

cat <<EOF

Installed and started.

  systemctl status ${SERVICE_NAME}
  journalctl -u ${SERVICE_NAME} -f

REFRESH THE KIT AFTER EVERY PAYMENT. A kit older than your real head installs
a split the provider prefers. Replace ${KIT_FILE} and restart the service.

THIS PROTECTS NOTHING WHILE IT IS STOPPED. There is no catch-up.

IT DOES NOT RENEW THE CHANNEL'S STORAGE LEASE. That is the clock that destroys
money outright. It will warn you in the log when the lease runs low; renewing
is done from the wallet.
EOF
