# What full mainnet actually requires

Written 2026-08-15, from the running system and the code, not from the plan.

Every claim here was verified by reading the source or querying the live Local
Pilot Hub and node. Where something is an inference it says so.

## The authority is the Hub, not this document

`GET /v1/readiness/mainnet` on a running Hub is the machine-readable answer.
It is evaluated by `MainnetReadinessV1::evaluate`
(`crates/l2-fast-pay-hub/src/readiness.rs:132-207`). Ask it rather than trusting
a checklist. As of writing, on the Local Pilot Hub:

```
profile                    local-pilot
production_mainnet_ready   false
payments_enabled           false
trustless_finality         false
unilateral_l1_enforceable  false

blockers
  external_monotonic_rollback_anchor_is_not_ready
  unilateral_l1_dispute_path_is_not_ready
  official_channelpay_mainnet_profile_not_enabled
```

## Two mainnet routes exist, and they are not the same thing

`readiness.rs:136-141` branches on `is_bounded_pilot`:

```rust
let is_bounded_pilot = profile == MAINNET_BOUNDED_PILOT_PROFILE;
if !external_rollback_anchor_ready && !is_bounded_pilot { blockers.push(...) }
if !l1_dispute_path_ready && !is_bounded_pilot { blockers.push(...) }
```

**Bounded pilot** waives the first two blockers. It is the route the code is
built to reach today: mainnet with deliberately bounded exposure.

**Full mainnet** does not waive them. It needs both to be genuinely true.

## Why full mainnet cannot be reached today

`HubState::health` (`crates/l2-fast-pay-hub/src/state.rs:532-534`):

```rust
external_rollback_anchor_ready: false,
l1_dispute_path_ready: false,
production_mainnet_ready: false,
```

These are constants. Nothing in the Hub crate ever sets them true; the only
assignments to `true` anywhere in the repo are on the agent wallet's own
unrelated struct (`agent-wallet-core/src/service/companion/witness.rs:180`) and
in a test (`service/l2/verification.rs:1567-1568`).

So the Hub's own evaluator cannot report full mainnet readiness by construction.
That is a deliberate fail-closed stance, not an oversight, and it should be the
last thing changed rather than the first.

### 1. Unilateral L1 dispute path

**Corrected 2026-08-16.** An earlier version of this file said the contract was
not deployed. That was wrong: it read the node's capability flag and treated a
configuration gap as a deployment gap.

`HPAYChannelExitV1` **is deployed and independently verified on chain**:

```
contract  ncJoygx8qBSHAw4sJbo5jTk1FJthJ1QLw
tx        6a369078f214f7c6f270a732dcb5ba4c53034906d33865b4a50a83819c0714a2
height    2522
```

The node's own `/query/hpay/channel-exit` endpoint — which re-derives the
deployment from its block store and VM state rather than trusting the Hub —
answers `deployment_action_verified: true`, matching `bytecode_sha3`, all 18
storage keys active.

The node's *capability* block nevertheless still reads:

```
channel_unilateral_exit          false
deployment.enabled               false
deployment.contract_address      null
deployment_tx_hash               null
deployment_height                null
```

So the remaining work is **node configuration, not deployment**: the fullnode
has to be told which contract address, transaction and height to treat as the
verified exit deployment before it will advertise the capability, and only then
does the Hub's readiness evaluator see `unilateral_l1_enforceable`.

One trap worth recording, found while checking this. A contract address is
`ContractAddress::calculate(deployer, nonce 0)` — a pure function of the
deployer, independent of bytecode. The Hub's nonce-0 slot derives to
`ajsciXwwYMAWiSewt41ijKaHfAHnnm1XP`, which is exactly the registry V2 contract.
Deploying the exit contract from the Hub identity would have collided with it.
`pilot-left` is the only correct deployer, and is the one that was used.

### 2. External monotonic rollback anchor

Requirements are already written up in
`docs/agent-wallet/EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md:29` and
`docs/l2/L2_SAFETY_MODEL.md:172`: a TPM or OS-keystore counter, or a remote
witness. Nothing implements it on the Hub side.

### 3. The flags must become measurements

Even with 1 and 2 built, `health()` returns constants. They have to be wired to
the real state or the gate stays closed for the wrong reason.

## "Full authenticated network witness", precisely

The phrase is owner prose, not a code identifier. It maps to exactly two error
strings, both in the registry V2 payment path:
`state/hvm_registry.rs:250` and `:320`.

What they compare is `HvmRegistryPaymentRequestV2.network_binding` against
`node.capabilities().l1_channel_network_binding()`. That comparison has two
halves and only one is authenticated:

- **The payer's half is a real signature.** The network binding is the first
  length-prefixed field in `payer_authorization_hash` under domain
  `HPAY/HVM-REGISTRY/PAYER-AUTHORIZATION/V1`
  (`hvm_registry_ledger.rs:20`, `:210-252`), verified against the payer's
  address at `:254-268`. A payer cannot be replayed onto another network.

- **The node's half is an unsigned self-report.** `FullnodeCapabilitiesV1::parse`
  (`node.rs:510-694`) is plain JSON parsing. There is no node key, no
  attestation, and no header, proof-of-work or Merkle check anywhere in the tree.

So today the check is a signed statement weighed against an assertion. "Full"
means making the node's half evidence.

A pattern already exists in-repo and is stricter than the Hub: the agent wallet
probes block 1 directly and compares it to a stored fingerprint
(`agent-wallet-core/src/node_binding.rs:222-250`).

What is already strong on this path, and should not be rebuilt: canonical
network-instance-id recomputation (`l1_channel.rs:88-101`), the pinned mainnet
genesis constant (`node.rs:22-23`), tip freshness with a policy the node cannot
renegotiate (`node.rs:25-26`, `:586-612`), bound submission where the node must
echo the exact transaction hash (`node.rs:1461-1527`), the TOCTOU double-read
around key use (`state/hvm_registry.rs:243-252` then `:313-322`), and exact-bytes
reconciliation with reorg detection (`state/hvm_registry_chain.rs:897-948`).

## Settlement gaps found and closed on 2026-08-15

- **Payer authorization never reached the Local Pilot.** The builder called
  `build_unsigned` with eight arguments where nine were required, and never
  produced the authorization signature the very next line demanded. No pilot
  payment could complete. Hidden because the module sits behind
  `local-pilot-tools`, which a plain `cargo test` does not compile.

- **Money did not come back after finalize.** The contract's `finalize` only does
  accounting; `settle()` moves `g_locked` into the claimable counters. HAC leaves
  only through an Action 14 `HacFromToTrs` triggering `PermitHAC`. No such
  transaction existed anywhere. Now built, with the watchtower reaching
  `ClaimLeftPayout` at status 4 on an unclaimed non-zero balance.

- **Confirmations were not anchored to a block hash**, so a reorg after the
  six-confirmation latch was undetectable. Now anchored, using the rule already
  proven in the pilot journal.

- **A real bug in the payment path.** Two Registry V2 rules were written into the
  Channel V1 constructor while the Registry V2 constructor had neither. `new()`
  could build an operation that failed its own validator.

## Still stranded: the Hub's own share

The left-party claim is exact: `c_status_ == FINAL`, `c_left_claimed_ == false`,
amount exactly `c_left_balance_`, and `c_left_claimed_` set on success.

The hub branch draws from `g_hub_claimable`, a counter **pooled across every
channel**, with no per-channel marker and only `amount <= claimable`. A hub claim
therefore cannot be made idempotent — a retry cannot distinguish "we already
claimed" from "another channel's payout moved the counter" — and cannot be
verified exactly afterwards.

**This needs a contract change, not a Hub change**: a per-channel
`c_hub_claimed_` marker mirroring `c_left_claimed_`. Until then the hub's settled
share stays inside the contract. That is a smaller and more contained problem
than the user's principal being stranded, which was the situation before.

## Not proven by anything yet

No Action 14 transaction has ever been executed by the HVM. Every test drives a
real `HubState` against an in-process mock. That these exact bytes satisfy
`PermitHAC` is unproven until the Local Pilot lifecycle runs it.

## Local Pilot lifecycle: exact resume point (2026-08-15)

Node, miner and Hub are running on private chain 7. Verified live:
`chain id 7, mainnet false`, node height 2836, Hub `deployment_profile: local-pilot`.

Journal state, read with `inspect`:

```
Hub prefunding  Confirmed      tx 592562024baabe9b7ea684d447a11786b71317befe613b8b918a75fcf603c3bb  height 2771
Deployment      Confirmed      tx 62687a9db41de1b860566a1e5aba9899b0927fe769919f37921a8d79ea79b638  height 2789
                contract       ajsciXwwYMAWiSewt41ijKaHfAHnnm1XP
Initialization  Not prepared   <-- resume here
Funding         Not prepared
```

The 200 HAC prefund and the deploy are done and must not be repeated: the
deployment protocol cost is exactly 20_000_000_000 Zhu = 200 HAC, and the Hub
balance is now ~10.4 HAC, consistent with it having been spent.

Identities and state, all under `%LOCALAPPDATA%\hpay\agent-local-pilot-v1`:

```
--left-identity-dpapi-file  hvm/pilot-left.identity.dpapi
--hub-identity-dpapi-file   hub/hub.identity.dpapi
--state-file                hvm/registry-v2-pilot-state.sealed.json
```

Addresses: left `1KCRLdAATCyeEPPtYn27RpJTdLV9Ueamk`,
hub `12ZCnDaGiZW9cZhYombd4mhUNLYnXcBjq7`.

The next step is `initialize`. Its exact preview was reviewed and is reproducible
(`preview-initialize` opens no node, no identity and no journal):

```
channel id           d47b203ff5dc783d1b421ba874756c6e
left deposit         1000000000 Zhu      hub deposit 0
challenge blocks     12                  reuse version 0
action kinds         ChainAllow(1041), ContractMainCall(44), ReqSignList(1044)
unsigned commitment  4808afbe1f2812612eb796c2ba50b4e702092f909f37dacb3d6e8b10cb0bbf0d
```

Remaining lifecycle after initialize: fund, activate, pay, then
challenge/respond/finalize, then crash/recovery. The claim path built today has
never been executed by the HVM; the finalize/claim leg is where that is first
proven.
