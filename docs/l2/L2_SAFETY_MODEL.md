# HPAY Wallet L2 Safety Model

Status: implemented for the custom HPAY Wallet Hub API v7 transport.

This document does not claim Official Hacash ChannelPay interoperability and
does not make the custom transport suitable for large-value mainnet use.

## Scope

The safety layer applies only to Fast Pay state transitions. It does not change:

- the Personal Wallet vault format or private key;
- L1 transaction creation, authorization, signing, or broadcast;
- the pinned Hacash full-node revision;
- the custom same-channel and cross-channel payment behavior;
- the zero wallet-fee policy for Fast Pay;
- Harbor or a future Agent Wallet.

## Durable state

The hub requires all four of the following before it advertises
`settlement_ready`:

1. a signing key;
2. a durable state-file path;
3. an independent 32-byte journal storage key.
4. a different independent 32-byte key that seals the complete durable state container with AES-256-GCM.

The journal storage key must not be the hub blockchain signing key. The hub
reads it from HACASH_HUB_JOURNAL_KEY_HEX.
The state key is read from HACASH_HUB_STATE_KEY_HEX. Mainnet refuses plaintext
state and refuses any reuse among signer, journal, and state keys.

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

Wallet Hub API v7 advertises explicit readiness fields for the external
rollback anchor, L1 dispute path, authenticated Official ChannelPay session, and
aggregate production readiness. The fullnode capability response also
advertises `features.channel_unilateral_exit` together with exact HVM deployment
evidence. The current Istanbul registry reports it as `false`: legacy Go
dispute action numbers collide with Istanbul TEX/AST kinds and cannot be copied
into mainnet. The candidate HVM path also remains false until the running node
confirms the pinned deployment transaction and exact on-chain contract edition
hash. Deployment is still insufficient because current channels use the native
ChannelPay settlement profile; Wallet, Hub, bill codec, recovery and watchtower
must explicitly adopt the separate HVM profile first. The node therefore does
not auto-enable the boolean from deployment evidence. Both Hub and wallet
require the boolean and the complete evidence, so an operator flag or edited
manifest cannot override the missing dispute path. The bounded trusted-Hub
pilot remains separately capped; cooperative recovery close stays available.
Testnet and local development retain the existing custom transport and all HPAY
safety extensions.

The HVM candidate now has a separate, non-authorizing evidence chain:

- exact per-channel binding and two-party initial recovery bill;
- a strict recovery bundle that rejects unknown fields;
- a full-node live snapshot of the exact contract code, 18 storage values and
  every active/recovery lease;
- a Hub verifier that binds the bundle and snapshot to the same fresh pinned
  mainnet node and network instance.

The exact recovery bundle and its live snapshot can now be written atomically
to sealed Hub state and the authenticated journal. The activation is
idempotent, survives restart and rejects contract or channel-incarnation reuse.
It remains deliberately separate from the native payment ledger and cannot
enable payments. HVM ledger creation, renewal/watchtower operations and full
restart reconciliation remain explicit gates.

## Remaining limits

The authenticated checkpoint is stored on the same local disk as the journal.
It detects partial rollback or tampering, but an attacker who can restore the
entire directory to one internally consistent older snapshot can also restore
the checkpoint. Strong rollback resistance needs an external monotonic anchor,
such as a TPM/OS-keystore counter or a remote witness.

An existing plaintext Hub state cannot be opened by the mainnet profile. It
must remain offline until a reviewed one-time migration tool can authenticate,
seal, verify, and preserve the original file. Manual editing or renaming is not
a migration and must not be used.

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
