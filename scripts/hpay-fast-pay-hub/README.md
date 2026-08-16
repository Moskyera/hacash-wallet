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

The installer asks for the Hub address, signer secret, and the initial pilot-user allowlist, verifies the local full-node capability endpoint, generates separate journal and sealed-state keys, installs a dedicated unprivileged service account and starts the Hub on loopback only. Signer, journal and state keys are always different.

Default and hard pilot limits are 1 HAC per payment, 10 HAC for a newly funded channel and 100 HAC aggregate active/reserved Hub TVL. Operators may configure lower values, never higher ones. The installer selects the explicit `mainnet-bounded-pilot` profile and refuses to start without at least one allowlisted Hacash user address.

## Verify

```bash
sudo systemctl status hpay-fast-pay-hub
curl http://127.0.0.1:8790/v1/health
curl http://127.0.0.1:8790/v1/readiness/mainnet
```

In `mainnet-bounded-pilot`, `payments_enabled` may become true only when the compatible node, signer, authenticated storage, allowlist, TVL and all caps are green. This is trusted-Hub operation, not a trustless L1 exit, and every wallet remains opted out until its owner explicitly accepts that dependency. The separate `mainnet-pilot` trustless profile remains blocked until the independent rollback anchor and unilateral L1 dispute path exist. A red readiness response is a safe refusal, not a reason to bypass the gate.

## Upgrade without replacing keys or state

Do not run `install.sh` over an existing installation. The installer deliberately refuses to replace the signer, journal key, state key, or durable state.

1. Stop the service: `sudo systemctl stop hpay-fast-pay-hub`.
2. Make offline backups of `/etc/hpay-fast-pay-hub` and `/var/lib/hpay-fast-pay-hub`.
3. Replace only `/opt/hpay-fast-pay-hub/fast-pay-hub` with the verified new release binary.
4. Start the service and confirm both health and mainnet readiness before restoring traffic.
5. Keep the backups until a restart and recovery drill succeeds.
## Security boundary

This is a bounded, Hub-coordinated mainnet pilot. It uses official Hacash ChannelPay bills without changing Hacash consensus, but current mainnet does not provide unilateral L1 finality for this flow. Start with small liquidity, keep wallet fees at zero, back up `/var/lib/hpay-fast-pay-hub` while the service is stopped, and do not advertise it as trustless.

Secrets live in `/etc/hpay-fast-pay-hub/hub.env`, readable only by root and the dedicated service group. Never upload that file, the Hub private key, the journal key, the state key or the full-node API token to GitHub.

The Hub ignores forwarded client-IP headers by default. If you explicitly configure `--trusted-proxy-ip`, use the one exact reverse-proxy address and make the proxy overwrite a single `X-Real-IP` value. Direct public access to port 8790 remains forbidden.
