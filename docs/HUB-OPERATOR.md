# Hacash Fast Pay - CSP Hub Operator Guide

For **operators** running a Channel Payment Service Provider (CSP) hub. End users only need the wallet.

## Components

| Piece | Binary | Role |
|-------|--------|------|
| CSP hub | `fast-pay-hub` | Wallet Hub API v4 |
| Fullnode | `hacash.exe` | Channel + L1 state |
| Hub wallet | Separate keypair | Signs as the hub party on each channel |

## Prerequisites

1. Hacash fullnode RPC (default `http://127.0.0.1:8080`)
2. Hub wallet funded with HAC
3. Open user-to-hub channels. Either channel side is supported.

## Hub wallet

Record two values:

- `HACASH_HUB_ADDRESS` - base58 address
- `HACASH_HUB_SECRET_HEX` - 64-char private key hex (must match address)

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
  --hub-fee-mei 0 \
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

## API v4

- `GET /v1/health` - discovery (returns `hub_address`)
- `POST /v1/fast-pay` - `{ payer, payee, amount, channel_id }` → `bill_hex`
- `GET /v1/fast-pay/{id}` - payment status

- `GET /v1/fast-pay/inbox/{payee}` retrieves routed payments awaiting the recipient signature
- `POST /v1/fast-pay/{id}/confirm` merges verified signatures and settles only when complete

## Cross-channel settlement

Routed payments require two open channels: payer-to-hub and recipient-to-hub. The hub must have enough HAC liquidity on the recipient channel. The flow is:

1. The hub prepares and signs both channel legs.
2. The payer verifies the complete payment intent and signs.
3. The payment becomes `awaiting_recipient` and appears in the recipient inbox.
4. The recipient verifies both channel legs and signs.
5. The hub verifies every signature and atomically commits both channel ledgers.

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
| Low balance | Increase payer funds or hub liquidity on the recipient channel |

See `crates/l2-fast-pay-hub` and `crates/wallet-core/src/l2_hub.rs`.