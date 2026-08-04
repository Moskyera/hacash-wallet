# HPAY Local Pilot Chain V1

This is a private, debug-only development network.

Every launcher prints:

```text
HPAY LOCAL PILOT CHAIN
PRIVATE DEVELOPMENT NETWORK
NO MAINNET FUNDS
NOT HACASH PUBLIC TESTNET
```

## Isolation

- Data: `%LOCALAPPDATA%\HPAY\agent-local-pilot-v1\data`
- Runtime: `%LOCALAPPDATA%\HPAY\agent-local-pilot-v1\runtime`
- P2P: `3197`, with discovery and inbound peers disabled
- API: `127.0.0.1:8197`
- Binary: dedicated `target\hpay-local-pilot\release\fullnode.exe`
- Mainnet fallback: none
- Official node fallback: none

The earlier height-zero process on port 8099 remains independent and untouched.

## Transaction readiness

The node reports `transaction_ready = true` only when all conditions hold:

1. The network is non-mainnet chain 7 with the exact Local Pilot kind and profile.
2. A real, canonically parsed block 1 exists.
3. Current height is at least 2.
4. The configured Agent pilot funding address has a positive confirmed HAC balance.
5. The required balance, submit, transaction query and reconciliation APIs are registered.

The wallet independently recomputes the network instance ID and requires the same block 1 fingerprint. Missing fields remain read-only compatible for Personal Wallet but can never enable Agent Wallet payments.
