# HPAY Fast Pay Hub one-click VPS package

This package installs the separate HPAY Fast Pay Hub as a locked-down Linux systemd service. It does not install, enable, disable or modify mining.

## Before installation

- Run a synchronized HPAY-compatible Hacash full node on `127.0.0.1:8080`.
- Keep `install.sh`, `hpay-fast-pay-hub.service` and the released `fast-pay-hub` binary in the same directory.
- Use a dedicated, low-balance Hacash address for Hub liquidity.
- Prepare an HTTPS domain and reverse proxy. Port `8790` must remain private.

## Install

```bash
chmod +x install.sh fast-pay-hub
sudo ./install.sh
```

The installer asks for the Hub address and secrets without printing them, verifies the local full-node capability endpoint, generates a separate journal key, installs a dedicated unprivileged service account and starts the Hub on loopback only.

Default limits are 0.1 HAC per payment and 0.1 HAC for a newly funded channel. The binary enforces a hard 1 HAC pilot maximum.

## Verify

```bash
sudo systemctl status hpay-fast-pay-hub
curl http://127.0.0.1:8790/v1/health
curl http://127.0.0.1:8790/v1/readiness/mainnet
```

`payments_enabled` becomes true only when the full node is the pinned Hacash mainnet, synchronized and compatible. A red readiness response is a safe refusal, not a reason to bypass the gate.

## Upgrade without replacing keys or state

Do not run `install.sh` over an existing installation. The installer deliberately refuses to replace the signer, journal key, or state.

1. Stop the service: `sudo systemctl stop hpay-fast-pay-hub`.
2. Make offline backups of `/etc/hpay-fast-pay-hub` and `/var/lib/hpay-fast-pay-hub`.
3. Replace only `/opt/hpay-fast-pay-hub/fast-pay-hub` with the verified new release binary.
4. Start the service and confirm both health and mainnet readiness before restoring traffic.
5. Keep the backups until a restart and recovery drill succeeds.
## Security boundary

This is a bounded, Hub-coordinated mainnet pilot. It uses official Hacash ChannelPay bills without changing Hacash consensus, but current mainnet does not provide unilateral L1 finality for this flow. Start with small liquidity, keep wallet fees at zero, back up `/var/lib/hpay-fast-pay-hub` while the service is stopped, and do not advertise it as trustless.

Secrets live in `/etc/hpay-fast-pay-hub/hub.env`, readable only by root and the dedicated service group. Never upload that file, the Hub private key, the journal key or the full-node API token to GitHub.