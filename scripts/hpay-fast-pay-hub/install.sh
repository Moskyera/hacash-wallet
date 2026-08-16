#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root: sudo ./install.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_BINARY="${SCRIPT_DIR}/fast-pay-hub"
INSTALL_DIR="/opt/hpay-fast-pay-hub"
STATE_DIR="/var/lib/hpay-fast-pay-hub"
CONFIG_DIR="/etc/hpay-fast-pay-hub"
ENV_FILE="${CONFIG_DIR}/hub.env"
UNIT_FILE="/etc/systemd/system/hpay-fast-pay-hub.service"
NODE_URL="http://127.0.0.1:8080"

if [[ ! -f "${SOURCE_BINARY}" ]]; then
  echo "Missing ${SOURCE_BINARY}. Keep install.sh beside the released fast-pay-hub binary." >&2
  exit 1
fi
if [[ ! -f "${SCRIPT_DIR}/hpay-fast-pay-hub.service" || ! -f "${SCRIPT_DIR}/README.md" ]]; then
  echo "The release package is incomplete. Keep the binary, service unit, README, and installer together." >&2
  exit 1
fi
if [[ -e "${ENV_FILE}" || -e "${STATE_DIR}/hub-state.json" ]]; then
  echo "An HPAY Fast Pay Hub installation already exists." >&2
  echo "This installer will not replace its signer, journal key, or state." >&2
  echo "Back up /etc/hpay-fast-pay-hub and /var/lib/hpay-fast-pay-hub, then follow the documented upgrade procedure." >&2
  exit 1
fi
for command in systemctl curl openssl; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "Install ${command} first, then run this installer again." >&2
    exit 1
  fi
done

read -r -p "Dedicated Hub Hacash address: " HUB_ADDRESS
if [[ ! "${HUB_ADDRESS}" =~ ^[1-9A-HJ-NP-Za-km-z]{30,40}$ ]]; then
  echo "The Hub address does not have a valid base58 shape." >&2
  exit 1
fi
read -r -p "Pilot user Hacash address (comma-separated for more than one): " ALLOWED_USERS
IFS=',' read -r -a PILOT_USERS <<< "${ALLOWED_USERS}"
if (( ${#PILOT_USERS[@]} == 0 )); then
  echo "At least one pilot user address is required." >&2
  exit 1
fi
for user_address in "${PILOT_USERS[@]}"; do
  if [[ ! "${user_address}" =~ ^[1-9A-HJ-NP-Za-km-z]{30,40}$ ]]; then
    echo "Every pilot user must be a comma-separated Hacash address without spaces." >&2
    exit 1
  fi
done
read -r -s -p "Dedicated Hub private key (64 hex characters): " HUB_SECRET
printf '\n'
if [[ ! "${HUB_SECRET}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "The Hub private key must contain exactly 64 hexadecimal characters." >&2
  exit 1
fi
read -r -s -p "Full-node API token (press Enter if the local node has none): " NODE_TOKEN
printf '\n'
if [[ -n "${NODE_TOKEN}" && ! "${NODE_TOKEN}" =~ ^[A-Za-z0-9._~-]{16,256}$ ]]; then
  echo "The node token must be 16-256 safe ASCII characters." >&2
  exit 1
fi
read -r -p "Maximum payment in Zhu [100000000 = 1 HAC]: " PAYMENT_CAP
PAYMENT_CAP="${PAYMENT_CAP:-100000000}"
if [[ ! "${PAYMENT_CAP}" =~ ^[0-9]+$ ]] || (( PAYMENT_CAP < 100000 || PAYMENT_CAP > 100000000 )); then
  echo "Payment cap must be 100000-100000000 Zhu (0.001-1 HAC)." >&2
  exit 1
fi
read -r -p "Maximum new channel funding in Zhu [1000000000 = 10 HAC]: " CHANNEL_CAP
CHANNEL_CAP="${CHANNEL_CAP:-1000000000}"
if [[ ! "${CHANNEL_CAP}" =~ ^[0-9]+$ ]] || (( CHANNEL_CAP < 100000 || CHANNEL_CAP > 1000000000 )); then
  echo "Channel cap must be 100000-1000000000 Zhu (0.001-10 HAC)." >&2
  exit 1
fi
read -r -p "Maximum aggregate Hub TVL in Zhu [10000000000 = 100 HAC]: " AGGREGATE_TVL_CAP
AGGREGATE_TVL_CAP="${AGGREGATE_TVL_CAP:-10000000000}"
if [[ ! "${AGGREGATE_TVL_CAP}" =~ ^[0-9]+$ ]] \
  || (( AGGREGATE_TVL_CAP < CHANNEL_CAP || AGGREGATE_TVL_CAP > 10000000000 )); then
  echo "Aggregate TVL must be at least the channel cap and at most 10000000000 Zhu (100 HAC)." >&2
  exit 1
fi

if [[ -n "${NODE_TOKEN}" ]]; then
  if ! printf 'header = "x-api-token: %s"\n' "${NODE_TOKEN}" | curl --config - --fail --silent --show-error --max-time 10 "${NODE_URL}/query/capabilities" >/dev/null; then
    echo "The protected HPAY full node did not answer ${NODE_URL}/query/capabilities." >&2
    exit 1
  fi
elif ! curl --fail --silent --show-error --max-time 10 "${NODE_URL}/query/capabilities" >/dev/null; then
  echo "The HPAY full node did not answer ${NODE_URL}/query/capabilities." >&2
  exit 1
fi

getent group hpayhub >/dev/null || groupadd --system hpayhub
id hpayhub >/dev/null 2>&1 || useradd --system --gid hpayhub --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin hpayhub
install -d -o root -g root -m 0755 "${INSTALL_DIR}"
install -d -o hpayhub -g hpayhub -m 0700 "${STATE_DIR}"
install -d -o root -g hpayhub -m 0750 "${CONFIG_DIR}"
install -o root -g root -m 0755 "${SOURCE_BINARY}" "${INSTALL_DIR}/fast-pay-hub"
install -o root -g root -m 0644 "${SCRIPT_DIR}/README.md" "${INSTALL_DIR}/README.md"

JOURNAL_KEY="$(openssl rand -hex 32)"
STATE_KEY="$(openssl rand -hex 32)"
TMP_ENV="$(mktemp "${CONFIG_DIR}/hub.env.XXXXXX")"
chmod 0640 "${TMP_ENV}"
chown root:hpayhub "${TMP_ENV}"
{
  printf 'HACASH_HUB_ADDRESS=%s\n' "${HUB_ADDRESS}"
  printf 'HACASH_HUB_SECRET_HEX=%s\n' "${HUB_SECRET}"
  printf 'HACASH_HUB_JOURNAL_KEY_HEX=%s\n' "${JOURNAL_KEY}"
  printf 'HACASH_HUB_STATE_KEY_HEX=%s\n' "${STATE_KEY}"
  printf 'HACASH_HUB_DEPLOYMENT_PROFILE=mainnet-bounded-pilot\n'
  printf 'HACASH_HUB_MAINNET_MAX_PAYMENT_HAC_ZHU=%s\n' "${PAYMENT_CAP}"
  printf 'HACASH_HUB_MAINNET_MAX_CHANNEL_FUNDING_HAC_ZHU=%s\n' "${CHANNEL_CAP}"
  printf 'HACASH_HUB_MAINNET_ALLOWED_USERS=%s\n' "${ALLOWED_USERS}"
  printf 'HACASH_HUB_MAINNET_MAX_AGGREGATE_TVL_HAC_ZHU=%s\n' "${AGGREGATE_TVL_CAP}"
  if [[ -n "${NODE_TOKEN}" ]]; then
    printf 'HACASH_NODE_API_TOKEN=%s\n' "${NODE_TOKEN}"
  fi
} > "${TMP_ENV}"
mv -f "${TMP_ENV}" "${ENV_FILE}"
unset HUB_SECRET JOURNAL_KEY STATE_KEY NODE_TOKEN ALLOWED_USERS PILOT_USERS AGGREGATE_TVL_CAP

install -o root -g root -m 0644 "${SCRIPT_DIR}/hpay-fast-pay-hub.service" "${UNIT_FILE}"
systemctl daemon-reload
systemctl enable --now hpay-fast-pay-hub.service

for _ in {1..20}; do
  if curl --fail --silent --max-time 2 http://127.0.0.1:8790/v1/health >/dev/null; then
    echo "HPAY Fast Pay Hub is installed and running locally."
    echo "Readiness: http://127.0.0.1:8790/v1/readiness/mainnet"
    echo "Publish it only through an HTTPS reverse proxy. Do not expose port 8790 directly."
    exit 0
  fi
  sleep 1
done

systemctl status hpay-fast-pay-hub.service --no-pager || true
journalctl -u hpay-fast-pay-hub.service -n 30 --no-pager || true
echo "The Hub did not become healthy. The service was installed but needs operator attention." >&2
exit 1
