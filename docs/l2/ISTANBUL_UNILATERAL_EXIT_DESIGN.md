# HPAY Istanbul unilateral exit design

Status: design gate only. No mainnet contract is deployed and no payment cap may be removed from this document alone.

## Prototype checkpoint

The full-node workspace now contains the canonical candidate source
`vm/contracts/hpay_channel_exit_v1.fitsh`, its reviewed manifest
`vm/contracts/hpay_channel_exit_v1.manifest.json`, and the executable test
`vm/tests/hpay_channel_exit.rs`. The test has two deliberately separate parts:

- a real Fitsh/HVM contract source that must compile against the pinned VM;
- a deterministic Rust reference state machine for the signed-bill rules.

The current vectors cover cooperative close, challenge, higher-serial response,
deadline finalization, stale replay, double close, wrong network, contract,
channel, reuse, party, total and challenge-policy bindings, wrong signer,
conservation failure and arithmetic overflow.

The private-chain vector now deploys that compiled contract through production
Type3/block execution, requires both party signatures for initialization,
executes both exact HAC funding hooks, lets a third-party watchtower submit a
challenge and a higher-serial response, finalizes only after the block-height
deadline, executes both exact payouts and rejects a replayed payout while the
contract still has enough balance. It also snapshots the chain before a
challenge, restores the pre-challenge state and proves that the exact signed
challenge can be resubmitted deterministically after the simulated reorg.

The pinned compiler currently produces contract SHA3
`11a2efc27a0c951bbc6977186eb58bd076dd331a785f3c57242cf54a72238349`.
The test fails if the source SHA-256, manifest, storage-key inventory or
bytecode commitment changes. This is a candidate commitment, not an approved
or deployed mainnet code hash.

The V1 funding profile is deliberately asymmetric and matches HPAY Hub
channels: the user (left party) deposits a positive amount and the Hub (right
party) deposits exactly zero. The contract opens after the exact user deposit.
It rejects a non-zero Hub principal so the contract cannot silently diverge
from the Hub and wallet channel binding.

Its settlement profile identifier is `hpay-hvm-channel-v1`. Native ChannelPay
channels must never be relabelled or implicitly migrated to this profile.

Every channel also needs its own strict
`hpay-hvm-channel-binding/1` record. The binding commits to the network
instance, per-channel contract address and deployment transaction, exact code
hash, channel id and reuse version, both parties, one-sided deposit and
challenge length. A global reference deployment is not evidence for another
channel instance.

The Hub now also defines `hpay-hvm-channel-bill/1` and the strict
`hpay-hvm-channel-recovery-bundle/1`. The bundle is valid only when serial 1
preserves the exact initial one-sided deposit and both bound parties have
signed the exact Fitsh/HVM bill hash. This is cryptographic recovery material,
not readiness by itself.

The HPAY full node exposes the read-only
`/query/hpay/channel-exit` evidence route. It verifies the caller-bound
deployment transaction and height, exact per-channel contract edition, all 18
storage values and the active/recovery lease budget of every key from the same
canonical node state. The Hub parses this response with a deny-unknown schema
and requires exact network instance, contract, channel incarnation, parties,
funding, open status and lease minima. The verified bundle can be persisted
atomically in sealed Hub state and its authenticated journal, but remains
separate from the payment ledger and cannot enable mainnet signing.

The deployment proof parses the canonical block at the claimed height and
requires exactly one transaction with the bound hash and exactly one matching
Action 40 `ContractDeploy`. The transaction main address plus deploy nonce must
derive the bound contract address, and the deployed `ContractSto` edition hash
must equal the pinned bytecode hash. A transaction and a same-code contract
that merely coexist on-chain are not accepted as deployment evidence.

The node capability response now publishes the candidate evidence but keeps
`features.channel_unilateral_exit=false`. A future `true` value requires the
manifest to opt in to an independently reviewed deployment, the running
mainnet node to prove all of the following from its own canonical state, and
Wallet/Hub funding, bill, recovery and watchtower code to use this exact HVM
settlement profile rather than the native ChannelPay profile:

- the exact deployment transaction exists at the pinned height;
- the exact contract address exists;
- the live contract edition hash equals the pinned bytecode SHA3;
- the observed chain height is not below the deployment height.

Hub and wallet parse this evidence strictly and reject missing, mismatched,
unconfirmed or downgraded evidence. Deployment evidence alone also cannot
enable the existing native profile. A separate reviewed integration change is
required; editing a manifest alone cannot enable mainnet Fast Pay.

The HVM storage cap permits at most 30,000 lease periods per key, but the
per-transaction storage-gas limit prevents prepaying that maximum atomically.
The prototype therefore proves a bounded initial lease and a permissionless,
bounded per-key `renew(key, periods)` call that a wallet or watchtower can
submit. The private-chain vector now also proves that an ordinary contract read
fails after live credit expires, and that a watchtower which prepaid recover
credit can restore the key without either channel secret. Production still
needs a compact reviewed storage layout, a durable renewal journal, expiry
alerts for every key and a fail-safe path before the recover window ends.

This checkpoint does **not** prove that contract storage leases survive the
full mainnet channel lifetime, that multi-block production reorg recovery is
safe, or that the watchtower and wallet journals reconcile every unknown
outcome. The node
capability therefore remains false and the bounded profile remains in force.

## Decision

The current native Hacash channel path remains the bounded trusted-Hub profile. The pinned Istanbul Rust full node registers native channel open and cooperative close, but it does not register a complete unilateral challenge and final-claim lifecycle.

The legacy Go core cannot be copied directly. It assigns channel dispute semantics to Actions 22, 23, 24, 26 and 27, while Istanbul assigns 22, 25 and 26 to TEX and AST. Registering both meanings would create a consensus and wire-format collision.

The non-consensus-change candidate for an uncapped profile is therefore an application contract built only from already-active Istanbul HVM/P2SH primitives. It must use a new explicit settlement profile and must never be confused with a native channel.

## Required contract state

Each channel stores:

- exact network instance and contract address;
- channel id and reuse version;
- left and right addresses;
- exact deposited HAC for each side;
- latest accepted bill serial and commitment;
- asserted balances and challenge deadline;
- status: funding, open, challenging or closed;
- final settlement transaction commitment.

The contract must reject SAT, HACD and HIP-20 balances until each asset path has its own reviewed conservation proof.

## Off-chain bill

Every bill is domain-separated as `HPAY/HVM-CHANNEL/V1` and commits, in fixed-width big-endian form, to the network instance, contract address, channel id, reuse version, both addresses, total deposit, challenge policy, monotonically increasing serial and both balances. Both channel parties sign the same canonical bytes.

A bill is valid only when both signatures verify, both balances are non-negative, their exact sum equals the immutable deposit, and the serial is greater than the stored challenge floor. A Hub receipt or local database record is not a substitute for these signatures.

## Exit state machine

1. Cooperative close: either party submits the latest fully signed bill. The contract verifies it and settles both balances immediately.
2. Unilateral challenge: either party submits a fully signed bill and starts a fixed block-height challenge window.
3. Response: either party may replace the asserted bill only with a valid fully signed bill having a greater serial.
4. Final claim: after the deadline, anyone may finalize the highest stored bill. Settlement is exactly the two committed balances.
5. There is no post-open no-bill refund. Absence of a newer bill cannot be
   proven on-chain, so such a timeout would let a user reclaim the original
   deposit after spending off-chain. Opening becomes usable only after the
   fully signed initial recovery bill is durable in both party journals.

No path may let a Hub choose balances, reuse an older bill, shorten the challenge window, redirect a payout, or require the Hub to remain online.

## Why HVM is preferred over a simple P2SH leaf

The P2SH transfer hook can observe witness bytes, action kind, destination, amount and block height, and it can verify signatures. That is enough for simple timelocks or HTLCs. A payment channel additionally needs durable highest-serial state and a replaceable challenge floor. HVM state is therefore required for the core dispute lifecycle; P2SH may be used only as an independently reviewed custody or recovery layer.

## Mandatory proof gates

The full node may report `features.channel_unilateral_exit=true` only after all of the following are complete:

- a versioned contract bytecode commitment is pinned;
- deploy, fund, pay, challenge, respond and finalize vectors pass on a private chain;
- old-state, replay, wrong-network, wrong-contract and channel-reuse attacks fail;
- conservation and overflow property tests pass;
- crash and reorg recovery are deterministic;
- a watchtower can submit a newer bill without wallet or Hub secrets;
- channel opening persists a fully signed initial recovery bill before the
  channel is advertised as ready;
- the authenticated Hub state atomically persists the exact recovery bundle
  and a fresh full-node live snapshot before ledger admission;
- every storage key has both a minimum active lease and a minimum recover
  window, with renewal journal and alerts;
- every per-channel contract deployment and binding is verified independently;
- testnet fault injection covers every state transition;
- an independent security review approves the bytecode and wallet integration;
- the exact deployed mainnet contract address and code hash are pinned by the wallet.

Only after those gates and small-value live mainnet tests may HPAY introduce an uncapped production profile. Removing the 1/10/100 pilot caps means removing artificial HPAY product ceilings; protocol numeric bounds, available balance, policy budgets and transaction-size limits always remain.

## Compatibility rule

Native ChannelPay bills and HVM-channel bills are separate protocols. They use separate channel ids, stores, journals, UI labels and recovery paths. Personal and Agent Wallets also keep separate HVM channel state and keys. Migration is never implicit.
