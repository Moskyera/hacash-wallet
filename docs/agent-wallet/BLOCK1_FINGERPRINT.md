# Block 1 fingerprint

## Local Pilot Chain V1 result

```text
Block 1 hash:
000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29

Network instance ID:
9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3
```

This is a local private chain fingerprint, not an official Hacash Testnet V3 fingerprint.

The node obtains height 1 bytes from its chain store, parses them with `protocol::block::build_block_package`, verifies the package height and stored canonical hash, then reports the lowercase hash. The wallet recomputes the instance commitment from:

```text
HPAY/NETWORK-INSTANCE/V1
network kind
chain id
mainnet flag
block 1 hash
node profile id
transaction format version
```

A mismatch in any field blocks Agent Wallet writes. The `/query/block/intro?height=1` result must also equal the capability payload.
