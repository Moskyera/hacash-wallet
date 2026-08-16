# HPAY Fast Pay and Official ChannelPay Compatibility Plan

Status: protocol research and local implementation audit complete. No official
ChannelPay interoperability claim is made by this document.

## Non-negotiable compatibility rules

1. The existing Personal Wallet remains unchanged outside its Fast Pay transport
   and channel-state safety boundary.
2. The current Wallet Hub API v4, same-channel flow, cross-channel flow,
   recipient confirmation, canonical bill validation, and zero-fee policy are
   preserved.
3. Wallet Hub API v4 is a custom HPAY HTTP/JSON transport. It is not version 4
   of the official Hacash ChannelPay protocol.
4. Official ChannelPay is added as a separate binary WebSocket transport. It
   does not replace or silently downgrade to the custom transport.
5. Harbor is not part of ChannelPay or Fast Pay.
6. Personal and future Agent Wallet channels, keys, state, and sessions must
   never be shared.

## 1. Protocol research report

### Reviewed upstream snapshots

- [`hacash/channelpay`](https://github.com/hacash/channelpay/tree/d63e4109f2f9f4471f0838536b68b240848a77ef),
  commit `d63e4109f2f9f4471f0838536b68b240848a77ef`.
- [`hacash/core`](https://github.com/hacash/core/tree/8bb265fc1a68acc0af3236354fba7386bac4d9c5),
  commit `8bb265fc1a68acc0af3236354fba7386bac4d9c5`.

These snapshots define the compatibility baseline. They are not treated as a
safe implementation to copy unchanged.

### Canonical protocol map

| # | Capability | Confirmed upstream behavior |
|---:|---|---|
| 1 | Framing | One binary WebSocket frame contains a one-byte message type followed by canonical Hacash field serialization. JSON is not used. |
| 2 | Version | `LatestProtocolVersion` is `1`. The stock client requires exact equality, but the stock server does not validate the incoming login version. This is version checking, not negotiation. |
| 3 | Login | Client connects to `wss://<gateway>/customer/connect`, sends message type 4 `MsgLogin`, and receives type 2 `MsgLoginCheckLastestBill`. |
| 4 | Channel/customer validation | CSP checks that the channel is open, service-listed, and that the claimed customer address is a channel side. Login has no wire-level proof-of-key challenge. |
| 5 | Channel address | Canonical readable forms are `address_service` and `address_channelId_service`. |
| 6 | Provider suffix | The last component is the alphanumeric, case-insensitive service name used for CSP resolution and routing. |
| 7 | Bill formats | Type 1 is routed simple-payment reconciliation. Type 2 is direct real-time channel reconciliation. |
| 8 | Reuse version | `ReuseVersion` is part of the signed channel state and must match the L1 channel reuse version. |
| 9 | Bill number | `BillAutoNumber` starts at 1 and each accepted state advances by exactly one. L1 challenge response requires a higher number. |
| 10 | Signatures | Prove-body hashes are included in one common transfer hash. Required signer addresses are sorted and signatures are positional. |
| 11 | Payment exchange | Message types 9 to 12 exchange prove bodies, signatures, errors, and final success. The payer signs after downstream signatures validate. |
| 12 | Route pre-query | Type 6 requests route candidates; type 3 returns an error or `PayPathForms`. |
| 13 | Route selection | The user selects a candidate and its ordered node path is placed in `TargetPath`. |
| 14 | Routing fees | Each relay advertises minimum, ratio, and maximum fees. Candidate fees are summed across the path. |
| 15 | Fee cap | `HighestAcceptanceFee` covers HAC only. The stock implementation can accept more than its name implies and has no equivalent satoshi cap. HPAY must enforce a stricter commitment. |
| 16 | Multi-CSP | Routes are graph paths of CSP nodes with a maximum path length of eight in the examined implementation. |
| 17 | Heartbeat | Type 15 heartbeat. Stock client sends every 14 seconds and closes after 60 seconds without an echo. |
| 18 | Disconnect/reconnect | Type 5 logout and type 1 displacement exist. There is no complete automatic reconnect state machine. |
| 19 | State recovery | Client stores one bill per channel and compares it during login. Upstream storage lacks an atomic journal and durable in-flight recovery. |
| 20 | Replay/rollback | Reuse version and next bill number provide partial protection. Transaction/session replay binding is incomplete, and the stock login can allow older state adoption. |
| 21 | Settlement | After routed success, participants store a Type-1 bill and client/CSP exchange types 13 and 14 to create a signed Type-2 reconciliation. |
| 22 | Dispute | Official core defines unilateral close/challenge/final-claim actions, but the stock ChannelPay client has no watcher, automatic response, retry, or confirmation tracker. |
| 23 | Offline behavior | The final receiver must be online. In-flight state is memory-only, and an offline channel owner has no built-in challenge protection. |
| 24 | Assets | Wire and bill structures carry HAC and Hacash-BTC fields. The examined upstream BTC channel-open action remains test/debug-only, so mainnet support is not assumed. |
| 25 | Routed atomicity | All channel prove-body hashes and required signers share one signed transfer. This is synchronized signing, not an HTLC. Crash/network uncertainty remains without durable in-flight state. |

### Official message flow

```text
route pre-query (6)
  -> route candidates and predicted fees (3)
  -> explicit route selection
  -> initiate payment (7)
  -> relay initiation across CSPs (8)
  -> prove bodies toward payer (9)
  -> signatures toward payer (10)
  -> error or success (11/12)
  -> persist Type-1 bills
  -> reconciliation request/response (13/14)
  -> persist signed Type-2 reconciliation
```

### Upstream behavior HPAY must not copy unchanged

- Login has no cryptographic challenge.
- Server-side protocol version enforcement is missing.
- The upstream fee cap is weaker than the user-visible promise.
- The selected route is not separately committed as a stable payment intent.
- Pending payments are not durably journaled.
- Automatic reconnect and challenge monitoring are missing.
- Transaction identifiers are not checked by every prove/sign/success handler.
- Some core bill validity helpers are stubs or require a separate consensus
  security audit.
- Local client bill writes are not crash-safe or rollback-resistant.

## 2. Existing implementation audit

### Custom capabilities that must be preserved

| Capability | Current home | Preservation rule |
|---|---|---|
| Wallet Hub API v4 endpoints | `crates/l2-fast-pay-hub/src/api.rs` | Keep as a custom legacy/development transport. |
| Same-channel and cross-channel routing | `crates/l2-fast-pay-hub/src/state.rs` | Keep both paths and recipient confirmation. |
| Shared multi-leg document | `crates/l2-fast-pay-hub/src/wire/` | Keep atomic validation of both channel legs. |
| Canonical bill parsing and signatures | `crates/wallet-core/src/l2_bill.rs` | Keep strict party, signer, channel, reuse, bill, amount, and balance checks. |
| L1 challenge-floor validation | `crates/wallet-core/src/l2_bill.rs` | Keep fail-closed comparison with known L1 state. |
| Wallet HTTP client and bill acceptance | `crates/wallet-core/src/l2_hub.rs` | Wrap; do not silently reinterpret as official ChannelPay. |
| Hub discovery/readiness | `crates/wallet-core/src/fast_pay.rs` | Keep custom capability checks with truthful labels. |
| No wallet fee on Fast Pay | payment policy and WalletService | Preserve. Official CSP/routing fees remain separate. |
| Protected-send restrictions | payment policy and WalletService | Preserve until exact prepared-bill authorization exists. |

### Compatibility gaps

- HTTP/JSON API v4 is not the official binary WebSocket protocol v1.
- There is no official login/latest-bill exchange, heartbeat, logout, or
  displacement handling.
- Route candidate pre-query, target path, transaction distinguish ID,
  prove/sign broadcasts, success/error handling, and official reconciliation
  are not implemented.
- The custom deterministic channel-ID convention must not be used in place of a
  real L1 channel ID for official ChannelPay.
- Current cross-channel support is one hub with two customer channels. It is
  not yet verified multi-CSP routing.
- Fast Pay is HAC-only. Protected satoshi fields do not prove Hacash-BTC Fast
  Pay support.
- Rust self-roundtrips do not prove Go/Rust wire compatibility.

## 3. Gap analysis

### Critical

1. The pinned Rust full node currently registers channel open/close actions but
   does not expose the complete official challenge/final-claim action path.
   The legacy Go core uses Actions 22, 23, 24, 26 and 27 for that lifecycle,
   but Istanbul already assigns 22, 25 and 26 to TEX/AST. Copying the old
   actions into the Rust registry would therefore be a consensus-breaking wire
   collision, not a compatibility fix. A reviewed non-conflicting network
   specification is required before implementation.
   High-value L2 use is blocked until dispute enforcement is implemented and
   testnet-proven.
2. Completed for partial/local tampering: hub and Personal Wallet operation
   state use authenticated hash-chained journals, atomic materialized state,
   and authenticated checkpoints. A complete rollback of all local files still
   needs an external monotonic anchor.
3. Completed for Wallet Hub API v4: unsigned state is durable before signing,
   the local signature is durable before submission, and uncertain outcomes
   enter recovery instead of automatic retry or L1 fallback.
4. Completed for Wallet Hub API v4: per-channel reservations, request
   commitments, reuse version, bill number, and state commitments fail closed
   on conflicting operations.

### High

- Completed: per-channel serialization and reservations cover every affected
  payer and recipient channel.
- Completed: stable client operation IDs, idempotency keys, and immutable
  request commitments survive restart.
- No authenticated login for the custom HTTP API.
- Completed: shared bounded native HTTP timeouts, no redirects, and bounded
  response bodies. Cryptographic provider-session authentication is still
  missing.
- Public inbox lookup leaks payment metadata and the public API lacks robust
  rate limits.
- Bill storage is private and atomic but not encrypted or rollback-detecting;
  its current comment must not claim encryption.
- Exact monetary parsing and overflow checks are implemented; future transports
  must reuse these fail-closed types rather than introduce parallel number logic.

### Medium

- Capability labels can overstate readiness.
- Legacy deterministic addressing and provider resolution need explicit
  compatibility boundaries.
- Recovery and uncertain-outcome UX are incomplete.
- Official fee presentation and route commitment types do not yet exist.

### Optional, after direct-channel safety

- Multi-CSP routing.
- Hacash-BTC Fast Pay.
- Background watchtower/challenge service.
- Agent Wallet channel support.

## 4. Architecture proposal

```text
Personal Fast Pay coordinator
  |
  +-- explicit transport selection
  |     +-- LegacyHttpFastPayAdapter
  |     |     `-- existing Wallet Hub API v4 behavior
  |     `-- OfficialChannelPayClient
  |           +-- ProtocolCodec
  |           +-- ProtocolStateMachine
  |           `-- WebSocketConnection
  |
  +-- shared safety layer
        +-- PaymentIntent / fee and route commitment
        +-- BillValidator
        +-- ChannelStateStore
        +-- ReconciliationBillStore
        +-- ReplayGuard
        +-- ChannelRecoveryService
        `-- ChallengeMonitor / L1DisputeBroadcaster
```

The existing `L2HubClient` implementation should be wrapped and exposed as
`LegacyHttpFastPayAdapter`; it should not be deleted or rewritten as a
WebSocket client.

The transport is selected before payment preparation. There is no automatic
fallback after a payment intent, bill, or signature exists.

### State machine

```text
idle
  -> connecting
  -> negotiating
  -> authenticating
  -> synchronizing
  -> ready
  -> preparing
  -> awaiting_user_approval
  -> signing
  -> signed_and_persisted
  -> submitting
  -> reconciling
  -> complete
```

Any network failure after signing enters `uncertain`, never an automatic retry.
Recovery compares durable local state, CSP state, and L1 challenge state before
another economic action is permitted.

### Fee commitment

The approval model must carry these independent values:

```text
HPAY wallet fee
CSP fee
routing fee
total amount debited
amount received
maximum fee approved by the user
selected route commitment
```

Legacy HTTP mode keeps its existing hard zero-fee invariant. Official mode may
have CSP/routing fees, but any post-approval change invalidates the prepared
payment.

## 5. Rollback-safe implementation plan

1. Completed: land this protocol map and capability-preservation contract.
2. Completed: use the truthful “Legacy Wallet Hub API v4” label.
3. Introduce transport-neutral payment intent, route, fee, receipt, and error
   types with unit tests.
4. Completed: wrap the existing HTTP client in `LegacyHttpFastPayAdapter` and
   prove behavior parity with the current test suite.
5. Completed: replace floating-point hub accounting with exact integer
   millimeis, checked arithmetic, and legacy-state migration.
6. Completed locally: authenticated versioned journals, state commitments,
   checkpoints, deletion detection, and deterministic fail-closed recovery.
   An external monotonic rollback anchor remains separate work.
7. Completed for Wallet Hub API v4: persist `prepared` before signing and
   `signed` before network submission.
8. Completed except provider-session authentication: per-channel reservations,
   idempotency keys, bounded timeouts, no redirects, and response limits.
9. Implement the official protocol codec from canonical message definitions
   and verify Go-to-Rust and Rust-to-Go golden vectors.
10. Implement one-CSP, one-direct-channel WebSocket state machine with strict
    version enforcement, authenticated session binding, heartbeat, safe
    disconnect, reconnect, and reconciliation.
11. Implement and test the required L1 challenge actions and broadcaster against
    testnet before enabling real-value official Fast Pay.
12. Only then evaluate multi-CSP and Hacash-BTC support.

Each step must be independently testable and must leave L1 send/receive and the
Personal Wallet vault unchanged.

## 6. Code implementation boundary

This stage preserves the protocol record, the behavior-preserving
`LegacyHttpFastPayAdapter`, exact integer hub accounting, checked
debit/credit and bill-number arithmetic, and fail-closed L1 balance parsing. It
now also adds authenticated journals, state-commitment chains, per-channel
reservations, client idempotency, persist-before-sign, bounded L2 HTTP, and
restart recovery. Existing API v4 endpoints, routing, recipient confirmation,
signatures, and zero-fee behavior remain intact.

Official network behavior is not enabled. Golden vectors from the pinned
official Go serializers now cross-parse with the Rust bill codec, but no real
compatible CSP run, external rollback anchor, authenticated official session, or
complete testnet-proven L1 challenge path is available. See
`L2_SAFETY_MODEL.md`.

## 7. Tests and verification required

Before official compatibility is claimed:

- Golden encoding/decoding vectors against the official Go implementation.
- Malformed/truncated/oversized binary message rejection.
- Version mismatch and invalid login rejection.
- Invalid provider suffix and channel ID rejection.
- Wrong reuse version and duplicate/decreasing bill number rejection.
- Altered balance, recipient, amount, fee, route, or signature rejection.
- Replay, duplicated frame, and out-of-order frame rejection.
- Timeout before signing and uncertain outcome after signing.
- Crash/reconnect recovery from the last durable signed state.
- Corrupt and rolled-back local state detection.
- CSP older-state rollback rejection.
- Concurrent-payment serialization and idempotency.
- Proof that L2 failure does not block L1 wallet operation.
- Testnet dispute simulation using the same node build shipped to operators.

Mock tests can prove local safety properties but cannot prove interoperability.
An end-to-end compatibility claim requires a real compatible CSP or an official
test fixture.

## 8. Production blockers

Real-value official ChannelPay remains disabled until all of the following are
closed:

1. Complete L1 challenge/final-claim actions in the selected full node.
2. Testnet-proven monitor, response builder, broadcaster, idempotent retry, and
   confirmation tracking.
3. External monotonic rollback anchoring. Local authenticated journals,
   checkpoints, and partial rollback/fork detection are complete, but a full
   consistent directory rollback cannot be detected from that directory alone.
4. Completed for Wallet Hub API v4: persist-before-sign and
   persist-before-submit guarantees.
5. Completed for Wallet Hub API v4: per-channel concurrency control and
   payment idempotency.
6. Authenticated CSP identity, bounded network I/O, and replay protection.
7. Completed in part: real pinned Go/Rust golden vectors cross-parse.
   Still required: a real CSP interoperability test covering the complete
   authenticated session and reconnect lifecycle.
8. Explicit user approval showing payee, amount, provider, route, all fees,
   total debit, and amount received.

Until then, existing Wallet Hub API v4 remains available only under its truthful
legacy/development compatibility label, with all current safety extensions
preserved.
