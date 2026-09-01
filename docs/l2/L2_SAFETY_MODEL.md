# HPAY Wallet L2 Safety Model

Status: implemented for the custom HPAY Wallet Hub API v4 transport.

This document does not claim Official Hacash ChannelPay interoperability and
does not make the custom transport suitable for large-value mainnet use.

## Scope

The safety layer applies only to Fast Pay state transitions. It does not change:

- the Personal Wallet vault format or private key;
- L1 transaction creation, authorization, signing, or broadcast;
- the pinned Hacash full-node revision;
- the custom same-channel and cross-channel payment behavior;
- the zero wallet-fee policy for Fast Pay;
- Harbor;
- the isolated Agent Wallet L2 namespace and HAP client described below.

## Durable state

The hub requires all three of the following before it advertises
`settlement_ready`:

1. a signing key;
2. a durable state-file path;
3. an independent 32-byte journal storage key.

The journal storage key must not be the hub blockchain signing key. The hub
reads it from `HACASH_HUB_JOURNAL_KEY_HEX`.

The Personal Wallet stores a separate operation journal under:

```text
HacashWallet/l2/personal/<wallet-hub-channel-binding>/
```

Its authentication key is derived from the wallet secret with HKDF-SHA256 and
the domain `HPAY/L2/JOURNAL/AUTH/V1`. The derived key and raw secret buffer are
zeroized after the journal is opened. Neither key is written to the journal.

## Journal guarantees

Every journal record contains:

- a strictly increasing sequence;
- the previous authenticated record hash;
- previous and next materialized-state commitments;
- wallet, provider, and channel bindings;
- channel reuse version;
- operation and idempotency identifiers;
- exact integer amount units;
- request and unsigned-state commitments;
- lifecycle phase;
- HMAC-SHA256 authentication.

The journal is appended and synchronized before the materialized state is
atomically replaced. The authenticated checkpoint is written last.

Startup fails closed on:

- a modified record or authentication tag;
- deletion, insertion, duplication, or reordering;
- a truncated final record;
- a broken state-commitment chain;
- a wrong wallet, provider, channel, or storage key;
- a stale materialized state;
- deletion of the journal while state or checkpoint metadata remains;
- a checkpoint newer than the journal.

## Persist-before-sign order

The hub uses this order:

```text
validate request and L1 channel
reserve every affected channel
persist unsigned bill and state commitment
sign with hub key
persist signed bill
return the signed response
```

The Personal Wallet uses this order:

```text
persist payment intent and stable idempotency key
receive and validate the prepared bill
persist unsigned bill and sign hash
sign with the Personal Wallet key
verify and persist the local signature
mark submitted
send confirmation
persist the final dispute-ready bill
mark committed
```

The local safety store rejects a purported signed bill unless it contains a
verified signature from the exact local wallet address.

## Idempotency and reservations

- Operation IDs are non-nil UUIDs.
- Idempotency keys are safe 16-to-128-character opaque values.
- The key is bound to an immutable SHA-256 request commitment.
- A repeated request returns the same operation and bill.
- Reusing a key or operation ID with different fields fails closed.
- Only one unresolved operation may reserve a channel.
- A cross-channel operation reserves both payer and recipient channels.
- Duplicate confirmation after a committed payment returns the same result
  only when the idempotency key and bill sign hash match.

## Crash and uncertain-outcome recovery

- A crash after unsigned persistence but before hub signing resumes the same
  durable operation and signs the same committed state.
- A restart after hub signing returns the same signed bill.
- A restart after commit returns the same completed result.
- A wallet restart before local signing resumes the same operation ID and key.
- A wallet restart after local signature persistence reuses the stored
  signature.
- A network error after submission enters `RecoveryRequired`.
- Automatic retry, a new L2 operation, and automatic L1 fallback are blocked
  after a signature may exist.
- An unreachable hub before any intent or signature exists is only a routing
  signal; normal L1 preview remains available.

## Mainnet fail-closed gate

Wallet Hub API v4 advertises explicit readiness fields for the external rollback
anchor, L1 dispute path, authenticated Official ChannelPay session, and aggregate
production readiness. These values are provider declarations, not proof of a
wallet capability. Mainnet selection now also requires an exact API version and
production profile, a valid passive CSP address, explicit zero hub fee,
settlement and cross-channel readiness, and a locally compiled authenticated
Official ChannelPay transport. That local transport gate is currently `false`,
so no remote response can enable Fast Pay on mainnet. The wallet remains on L1.
Testnet and local development retain the existing custom transport and all HPAY
safety extensions.

## Remaining limits

The authenticated checkpoint is stored on the same local disk as the journal.
It detects partial rollback or tampering, but an attacker who can restore the
entire directory to one internally consistent older snapshot can also restore
the checkpoint. Strong rollback resistance needs an external monotonic anchor,
such as a TPM/OS-keystore counter or a remote witness.

Large-value mainnet use also remains blocked by:

- no real compatible CSP interoperability run;
- incomplete, testnet-proven L1 challenge, response, and final-claim automation;
- no independently reviewed watchtower or dispute broadcaster;
- no authenticated Official ChannelPay session implementation.

The isolated fixture loader in
`crates/wallet-core/src/channelpay_interop.rs` now verifies checked-in vectors
generated by the pinned official Go serializers. The manifest SHA-256 is pinned
by the Rust test, upstream revisions must match, and every binary vector passes
its own SHA-256 and format validation. The official Go complete-document bytes
are parsed and re-serialized by the Rust wire codec. This proves selected codec
parity only; it does not enable a network transport or prove CSP interoperability.

## Agent Wallet Hacash L2 boundary

The Agent Wallet uses the same `hacash-l2-protocol` ecosystem, but never the
Personal Wallet's L2 account or files. Each Agent Wallet has a distinct
namespace derived only from its validated `AgentWalletId`:

```text
agent/wallets/<AgentWalletId>/l2/
  client.json
  journal.jsonl
  receipts/
  channels/
```

Two Agent Wallet IDs produce different namespaces. Unknown or traversal-shaped
IDs fail before path construction, and the trusted manager refuses an ID that
is not present in the Agent registry. The agent/LLM-facing connector is not
given these paths.

The current `HacashL2ProtocolClient` is read-only. It probes the HAP manifest
and fails closed on a protocol, origin, endpoint, or signing-contract mismatch.
It also fetches `/v1/net/self` and verifies the fresh protocol-2.x
`HACASH_L2_HELLO_V1` commitment: provider and origin, complete channel-ad hash,
Hacash address derivation, compressed secp256k1 key, SHA3-256 signature, replay
window, and clock skew. Unsigned, stale, cross-origin, substituted-key and
protocol-1.x hellos never establish provider identity.

First contact is deliberately not trusted automatically. The owner must confirm
the full 64-hex HPAY provider fingerprint. The accepted identity is stored in
the encrypted, journal-committed state of that exact Agent Wallet, not in the
public `l2/client.json` path. Every later probe compares the new signed hello to
that pin; a changed key, address, provider ID or origin fails closed. Existing
pins cannot be overwritten through the first-contact API, so rotation still
requires a separate explicit recovery ceremony.

The client still has no payment, inbox-signing, receipt-acceptance, or generic
signature method. A remote hub cannot turn on mainnet spending through
optimistic capabilities. Hub `settled` is recorded only as
`hub_coordinated_not_l1`.

Before Agent L2 payments can be enabled, HPAY still needs a reviewed provider
rotation ceremony, durable content-bound idempotency/reconnect recovery, exact
quote-to-approval binding, signed receipt verification, testnet-proven L1
dispute recovery, unilateral exit compatibility, real multi-hub fault tests,
and an independent security audit.
