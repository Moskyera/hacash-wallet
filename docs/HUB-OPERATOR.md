# Hacash Fast Pay — CSP Hub Operator Guide

For **operators** running a Channel Payment Service Provider (CSP) hub. End users only need the wallet.

## Components

| Piece | Binary | Role |
|-------|--------|------|
| CSP hub | `fast-pay-hub` | Wallet Hub API v1 |
| Fullnode | `hacash.exe` | Channel + L1 state |
| Hub wallet | Separate keypair | Signs as channel right party |

## Prerequisites

1. Hacash fullnode RPC (default `http://127.0.0.1:8080`)
2. Hub wallet funded with HAC
3. Channels: user = left, hub = right

## Hub wallet

Record two values:

- `HACASH_HUB_ADDRESS` — base58 address
- `HACASH_HUB_SECRET_HEX` — 64-char private key hex (must match address)

## Build

```bash
cargo build -p l2-fast-pay-hub --features server --bin fast-pay-hub --release
```

## Run

```bash
export HACASH_HUB_ADDRESS=1YourHubAddress
export HACASH_HUB_SECRET_HEX=your64charhex

./target/release/fast-pay-hub \
  --listen 127.0.0.1:8790 \
  --node-url http://127.0.0.1:8080 \
  --hub-fee-mei 0.001 \
  --state-file ./hub-state.json
```

Health: `curl http://127.0.0.1:8790/v1/health`

## Production

- Use `--state-file` for persistence
- TLS reverse proxy in front of hub
- Never commit hub secret; `chmod 600` on state + env files
- Firewall: public 443 only; hub port internal

### systemd example

```ini
[Service]
Environment=HACASH_HUB_ADDRESS=1YourHubAddress
Environment=HACASH_HUB_SECRET_HEX=...
ExecStart=/opt/hacash/fast-pay-hub --listen 127.0.0.1:8790 \
  --node-url http://127.0.0.1:8080 --state-file /var/lib/hacash-hub/state.json
Restart=on-failure
```

## API v1

- `GET /v1/health` — discovery (returns `hub_address`)
- `POST /v1/fast-pay` — `{ payer, payee, amount, channel_id }` → `bill_hex`
- `GET /v1/fast-pay/{id}` — payment status

## Windows dev

```bat
set HACASH_HUB_ADDRESS=1YourHubAddress
set HACASH_HUB_SECRET_HEX=your64charhex
scripts\START-DEV-STACK.bat
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Address mismatch | Secret must match `HACASH_HUB_ADDRESS` |
| Channel not found | Check fullnode URL + channel id |
| Missing hub signature | Set `HACASH_HUB_SECRET_HEX` |
| Low balance | Increase user channel deposit |

See `crates/l2-fast-pay-hub` and `crates/wallet-core/src/l2_hub.rs`.