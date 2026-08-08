# Canonical testnet identity audit

Date: 2026-08-02

## Decision matrix

| Question | Verified answer | Evidence |
|---|---|---|
| Canonical Hacash Testnet V3 found | No | Official fullnode branches, tags, source and public node instructions contain no authoritative Testnet V3 profile. |
| Canonical block 1 found | No | `mint/src/genesis/block.rs` defines the universal height 0 genesis, not a Testnet V3 block 1. |
| Authoritative block 1 fingerprint found | No | No source, release, snapshot or official documentation publishes one. |
| Bootstrap peers found | No | Published peers are mainnet peers only. |
| Public peer discovery found | No | No verified non-mainnet discovery source exists. |
| Verified snapshot found | No | No authoritative non-mainnet snapshot with hash and chain proof exists. |
| Local mining possible | Yes | Fullnode miner routes and `poworker` use the real pending and success block pipeline. |
| Consensus coinbase maturity found | No separate maturity | `TransactionCoinbase::execute` credits the reward through normal state execution. The 16-block pool delay is pool payout policy, not consensus maturity. |
| Local wallet funding possible | Yes | Mine to a controlled address, or perform a normal on-chain transfer from a controlled mined address. |
| Chain ID 7 sufficient identity | No | It does not identify block 1, instance, profile, API contract or transaction format. |

## Selected path

The selected path is `HPAY Local Pilot Chain V1`.

It is not Hacash public testnet and must never be presented as one. Its stable identity is:

```text
network kind: local_pilot_v1
node profile: hpay-local-pilot-chain-v1
chain id: 7
mainnet: false
transaction format: 2
block 1: canonical hash of the first actually mined block
instance id: SHA-256 commitment over all stable fields above
```

The public Hacash instructions reviewed describe mainnet node operation. They do not establish a canonical Testnet V3 identity.
