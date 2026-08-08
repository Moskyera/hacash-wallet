# Live chain transaction report

Date: 2026-08-02

```text
Evidence category: LOCAL_PRIVATE_CHAIN
Network kind: local_pilot_v1
Block 1: 000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29
Network instance: 9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3
Current observed height: 12
Real mining: completed
Agent Wallet created: no
Agent Wallet funded: no
Transaction ready: no
Agent payment transaction: not executed
Physical Android witness: not executed
HPAY wallet fee: 0
```

No Agent payment was attempted because there is no user-created Agent Wallet address, spendable Agent balance or physical Android witness. This is the required fail-closed result. The mined bootstrap blocks are real Local Pilot chain activity but are not a public testnet transaction.

The current source passed Android ARM64 compilation with the pinned NDK and the
strict generated-project validator. The older debug APK predates this source
and is not accepted as transaction or device evidence.
