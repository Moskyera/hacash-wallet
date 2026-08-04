# HPAY Live Testnet Transaction Report

Date: 2026-08-02

Evidence category: not executed; no live transaction claim.

| Field | Result |
|---|---|
| New testnet Agent Wallet | No |
| Testnet address | Not executed |
| Funded balance | No |
| Controlled recipient | Not available |
| Actual HAC testnet transaction | No |
| Transaction ID | Not executed |
| Amount units | Not executed |
| Hacash network fee units | Not executed |
| HPAY wallet fee | `0` |
| Total debit units | Not executed |
| SignedPreBroadcast witness | Not executed |
| Submitted witness | Not executed |
| ReconciledFinal witness | Not executed |
| Reservation released | Not executed |
| Duplicate signature/broadcast | Not executed |

The isolated node reported chain 7 and `mainnet=false`, but remained at height
0 with no canonical block-one fingerprint. A physical Android companion and a
funded Agent Wallet were also unavailable. These are mandatory stop conditions,
so no wallet was created, no signature was requested, and no submission was
attempted. Mainnet and official-node fallback were not used.

The existing automated suite remains the only evidence for one-signature,
one-submit, timeout, restart, witness ordering, exact-hash reconciliation, and
reservation-release behavior. It is not live-network or physical-device proof.
