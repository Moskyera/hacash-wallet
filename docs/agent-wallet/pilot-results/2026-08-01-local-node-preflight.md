# Local Node Preflight Evidence

- Session ID: `2026-08-01-local-node-preflight`
- Evidence category: `LIVE_CUSTOM_NODE`
- Operation: read-only capability and block-one queries
- Node-reported name/version: `hacash-fullnode 1.0.10`
- Node-reported build: `2026/7/10 #1`
- Capability API: version 1, parsed successfully
- Chain: id `0`, `mainnet=true`, height `769553`
- Istanbul: active at evaluation height `769554`
- Transaction Type 2: enabled
- Action kind 1: enabled
- Testnet V3 binding: failed; endpoint is mainnet
- Separate testnet data directory: not verified
- Wallet connected: no
- Transaction signed or broadcast: no

## Result

The endpoint is not eligible for the Agent Wallet testnet Pilot. The preflight
stopped fail closed at the network binding before any Agent Wallet connection,
approval, signing, or submission. This evidence does not authorize mainnet
Agent Wallet use and does not count as a completed live testnet pilot.
