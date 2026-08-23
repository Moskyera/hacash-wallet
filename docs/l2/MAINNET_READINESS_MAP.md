# What full mainnet actually requires

Written 2026-08-15. Re-measured 2026-08-17 against the real Hacash mainnet
fullnode, from the running system and the code, not from the plan.

Every claim here was verified by reading the source or querying a live Hub and
node. Where something is an inference it says so.

## The authority is the Hub, not this document

`GET /v1/readiness/mainnet` on a running Hub is the machine-readable answer.
It is evaluated by `MainnetReadinessV1::evaluate`
(`crates/l2-fast-pay-hub/src/readiness.rs:287-539`). Ask it rather than trusting
a checklist.

The measurement that matters is a mainnet-profile Hub pointed at the real
Hacash mainnet fullnode, not a pilot-chain one. Two such Hubs, same binary,
same node (`http://127.0.0.1:8080`, chain id 0, mainnet true, height 774025,
block 1 `001e231c...db56`), same caps, no rollback witness configured on either.

**`mainnet-bounded-pilot`, served verbatim on 2026-08-17:**

```
profile                    mainnet-bounded-pilot
payments_enabled           true
close_enabled              true
mainnet_detected           true
rollback_anchor            null
trustless_finality         false
unilateral_l1_enforceable  false
trusted_bounded_pilot      true

blockers        []
close_blockers  []
```

That empty list is the most actionable fact in this document. **The Hub side of
the bounded mainnet pilot is finished**, with no witness and no exit contract,
and it says so on the wire rather than in a plan.

Not a document-only claim. The same `POST /v1/fast-pay` body put to both Hubs:

```
mainnet-bounded-pilot  {"error":"not found: channel 00112233445566778899aabbccddeeff"}
                       past the whole mainnet money gate, refused by the L1 lookup

mainnet-pilot          {"error":"Fast Pay Hub is unavailable"}
                       hub log: mainnet payment gate blocked:
                         external_monotonic_rollback_anchor_is_not_ready;
                         unilateral_l1_dispute_path_is_not_ready;
                         fullnode_does_not_report_verified_registry_unilateral_exit
```

So the Hub is not what stops a mainnet payment on the bounded profile.

**`mainnet-pilot`, same binary, same node, same flags, same moment:**

```
profile                    mainnet-pilot
payments_enabled           false
close_enabled              true
trusted_bounded_pilot      false

blockers
  external_monotonic_rollback_anchor_is_not_ready
  unilateral_l1_dispute_path_is_not_ready
  fullnode_does_not_report_verified_registry_unilateral_exit
close_blockers  []
```

`close_blockers` is empty on both, so cooperative close is available on both
profiles even while the full profile refuses payments (`readiness.rs:427-458`
filters the waived and admission identifiers out of `blockers`).

Two identifiers that look like blockers and are not. The control, the same two
profiles pointed at the pilot node on 8197 instead:

```
mainnet-pilot          blockers  external_monotonic_rollback_anchor_is_not_ready
                                 unilateral_l1_dispute_path_is_not_ready
                                 mainnet_pilot_requires_hacash_mainnet_fullnode
                                 fullnode_below_pinned_mainnet_checkpoint_765432
                                 fullnode_does_not_report_verified_registry_unilateral_exit
mainnet-bounded-pilot  blockers  mainnet_pilot_requires_hacash_mainnet_fullnode
                                 fullnode_below_pinned_mainnet_checkpoint_765432
```

`mainnet_pilot_requires_hacash_mainnet_fullnode` (`readiness.rs:389-391`) and
`fullnode_below_pinned_mainnet_checkpoint_765432` (`readiness.rs:392-397`) are
artefacts of pointing a mainnet profile at the wrong chain. They vanish against
the real mainnet node, as the two documents above show, and are not work.

## Two mainnet routes exist, and they are not the same thing

`readiness.rs:328-364` branches on `is_bounded_pilot`:

```rust
let is_bounded_pilot = profile == MAINNET_BOUNDED_PILOT_PROFILE;
// the identifier is computed either way; only which list it lands in changes
let sink = if is_bounded_pilot { &mut disclosed_blockers } else { &mut blockers };
```

The waiver moves an identifier between lists. It does not delete it. Until
2026-08-23 it did delete it: the whole branch was skipped on the bounded
profile, so the served document read `"blockers":[],"close_blockers":[]` while
`no_watcher_answers_for_an_offline_owner` was outstanding, and an empty list was
indistinguishable from a clean Hub. `disclosed_blockers` is the third list and
the invariant is in the type, not in a comment: `blockers` and
`disclosed_blockers` are disjoint, and their union is everything the Hub knows
to be outstanding. `payments_enabled` and `close_enabled` still read only the
first two, so nothing the bounded pilot was allowed to do changed.

The dispute-path branch is gated on the profile again at `readiness.rs:406-409`,
which raises `fullnode_does_not_report_verified_registry_unilateral_exit` on
`mainnet-pilot` only.

What the disclosure says matters as much as that it exists. The first version of
the plain-words limitation claimed that a provider settling an old receipt while
the owner sleeps takes the difference from them. On the rail this build ships
that is backwards: `HvmRegistryBindingV2::validate` refuses any binding with a
non-zero hub deposit, and the bill ledger only ever subtracts from the left
balance, so every later receipt pays the owner strictly less and a stale one
pays them more. Answering a stale challenge hands money back, which is why
`decide_user_exit_action` finishes what is standing instead of responding and
`registry_response_watch` refuses to sign such a response at all. The real
exposure, and what the limitation now says, is that the ending does not happen
by itself for an absent owner, and that the protection above is a property of
those two checks rather than a guarantee from the protocol.

**Bounded pilot** waives those three blockers and nothing else. It is the route
the code is built to reach today, and has reached: mainnet with deliberately
bounded exposure. Everything else the full profile demands is demanded of the
bounded profile identically:

| demand | where |
| --- | --- |
| Hub signer plus authenticated durable storage | `readiness.rs:325-327` |
| payment and channel-funding caps inside their compile-time ceilings | `readiness.rs:370-383`, `readiness.rs:833-848` |
| the fullnode reports mainnet, at or above height 765432 | `readiness.rs:389-397` |
| action 2 channel open and action 3 cooperative close enabled | `readiness.rs:398-405` |
| a configured user allowlist and aggregate TVL inside its cap | `readiness.rs:747-773` |
| a zero wallet fee, re-checked at the signing boundary | `readiness.rs:782-818` |

**Full mainnet** does not waive them. It needs all three to be genuinely true.

What the waiver costs, in a sentence the document does not soften:
`trustless_finality` and `unilateral_l1_enforceable` both read `false` on the
bounded profile, measured above, so bounded-pilot money is Hub-dependent. If the
Hub is restored from an older backup there is no external counter to catch it,
and if the Hub refuses to co-sign a close there is no unilateral L1 exit. Against
that, the exposure cannot exceed the compile-time ceilings of 100000000 zhu per
payment, 1000000000 zhu per channel and 10000000000 zhu aggregate
(`readiness.rs:20-22`), an operator may configure lower and no runtime flag can
raise them, every channel needs an allowlisted user, and the flags name the trade
rather than hiding it.

## Why full mainnet cannot be reached today

`MainnetReadinessV1::evaluate` (`crates/l2-fast-pay-hub/src/readiness.rs:528-531`)
publishes the measurement:

```rust
trustless_finality: external_rollback_anchor_ready && l1_dispute_path_ready,
unilateral_l1_enforceable: l1_dispute_path_ready,
```

Both inputs are measurements taken by `HubHardGuarantees::measure`, on the
endpoint that pays for the evidence. `trustless_finality` needs the external
monotonic rollback anchor as well as the dispute path, so it reads `false` on
any Hub whose anchor evidence is missing, unverified or stale — which is every
Hub with no witness configured. That is a fail-closed stance, not an oversight.

Both inputs are also *re-measured inside `evaluate`* against the evidence the
same document publishes — `rollback_anchor` and `fullnode_capabilities` — and
kept only where the two agree. `evaluate` is a public function taking two plain
booleans, and before that conjunction it would write a caller's `true` straight
onto the wire beside a `fullnode_capabilities` block carrying no verified
registry deployment and a `rollback_anchor` of `null`: a document contradicting
itself in the direction of a guarantee. Passing `true` can now only fail to make
a flag `false`; it can never make one `true`. Pinned by
`no_argument_list_can_publish_a_guarantee_the_evidence_does_not_support`.

### `/v1/health` publishes none of this, on purpose

`HubState::health` performs no fullnode I/O, so it has no evidence to weigh. It
used to mirror `external_rollback_anchor_ready`, `l1_dispute_path_ready` and
`production_mainnet_ready` as conservative constants; those fields were removed
from `HubHealth` on 2026-08-16, because a flag that is structurally always
`false` cannot distinguish "not measured here" from "proven absent", and a
wallet gating on one could never be un-bricked by the guarantee arriving.
`/v1/readiness/mainnet` is now the only place a guarantee is published, and
gating on `HubHealth` for one is a compile error.

`HubHardGuarantees::production_mainnet_ready` still exists as the Hub's internal
aggregate measurement (`readiness.rs:1995-2001`); it is simply no longer exported
on the liveness endpoint.

### 1. Unilateral L1 dispute path

**Corrected a third time, 2026-08-17: the gate was measuring the wrong
contract.** Everything below this paragraph was written about
`HPAYChannelExitV1`, settlement profile `hpay-hvm-channel-v1` — the V1
per-channel contract. That is not the contract this system uses.
`measure_l1_dispute_path_ready` required
`ChannelUnilateralExitEvidence::is_verified_mainnet_deployment`, and that
evidence type is hard-bound to the V1 profile
(`crates/l2-fast-pay-hub/src/node.rs:33`). The path that was built, proven and
shipped is the shared registry, `hpay-hvm-shared-registry-v2`
(`crates/l2-fast-pay-hub/src/hvm_registry.rs:17`), and the fullnode fed only V1
evidence: V2 had a snapshot endpoint and the `hpay_channel_registry_query` flag
and no deployment-verified capability at all.

The consequence was not conservative. Deploying registry V2 to Hacash mainnet
would have left `unilateral_l1_enforceable` reading `false` forever, because the
gate was looking at a different contract — and a V1 deployment would have moved
a flag about a rail no user travels. The measurement is now bound to V2:
`RegistryUnilateralExitEvidence` (`crates/l2-fast-pay-hub/src/node.rs:511`) and
the fullnode's `channel_registry_unilateral_exit_evidence`
(`../hacash-fullnodedev/app/src/hpay_channel_registry.rs:196`), which re-derives
the deployment from the node's own block store exactly as V1 does and
additionally proves the two V2-only bindings: the deploying transaction really
carries this artifact, and its 32-byte constructor argument is the node's own
network instance.

**The flag did not move.** Nothing is deployed on Hacash mainnet, so the honest
V2 answer is still `false` — now for the right reason. Section 2 below, the rail
migration, is what the correction does *not* change: it was always the expensive
part, and it is still open.

**Corrected twice before that. Read the dates.** The 2026-08-15 version said the contract
was not deployed. The 2026-08-16 version overcorrected: it found the deployment,
did not check which chain it was on, called it verified on chain, and concluded
that the remaining work was fullnode configuration. Both halves of that were
wrong, and it is the most expensive wrong instruction this document has carried,
because it points an owner at an afternoon of configuration in place of protocol
work in another repository.

**`HPAYChannelExitV1` is deployed on the private pilot chain only, chain id 7.**

```
contract  ncJoygx8qBSHAw4sJbo5jTk1FJthJ1QLw
tx        6a369078f214f7c6f270a732dcb5ba4c53034906d33865b4a50a83819c0714a2
height    2522
chain     7   (private pilot chain, not Hacash mainnet)
```

Measured 2026-08-17, the same `/query/hpay/channel-exit` query put to both nodes:

```
pilot node   127.0.0.1:8197  ret 0, "chain_id": 7, deployment_action_verified true,
                             all_keys_active true, bytecode_sha3 matches
mainnet node 127.0.0.1:8080  ret 1, "HPAY HVM channel snapshot does not match the
                             requested chain and deployment height"
```

Height 2522 can never be a verified mainnet deployment whatever the fullnode is
told, because `ChannelUnilateralExitEvidence::is_verified_mainnet_deployment`
requires `deployment_height >= HACASH_MAINNET_MIN_SAFE_HEIGHT`, which is 765432
(`crates/l2-fast-pay-hub/src/node.rs:24`, checked at
`crates/l2-fast-pay-hub/src/node.rs:395`). The real mainnet node is at height
774025 and its exit evidence carries `deployment.enabled: false`,
`contract_address: null`, `deployment_verified: false`.

The capability is not withheld for want of configuration either. It is a
literal:

```rust
// ../hacash-fullnodedev/app/src/node_api.rs:442, the sibling repository this
// crate already path-depends on
let channel_unilateral_exit = false;
```

The comment above it (`node_api.rs:437-441`) states the precondition: the
wallet, Hub, bill codec, funding path and watchtower must first bind every
channel to this exact contract profile, and the capability must never be
auto-enabled from deployment evidence alone.

**The action-number collision is not the obstruction. Corrected 2026-08-17.**
The comment at `node_api.rs:505-509` records that the *legacy Go* action numbers
22, 25 and 26 collide with Istanbul TEX and AST
(`AST_ACTION_KINDS = &[25, 26]`, `TEX_ACTION_KIND = 22`, `node_api.rs:20-21`).
That collision is real, and `HPAYChannelExitV1` sidesteps it completely by
putting the state machine in an HVM contract reached through the *contract*
actions `CONTRACT_ACTION_KINDS = &[40, 41, 44]` (`node_api.rs:24`). The contract
implements the path itself — `function external challenge(` and
`function external respond(` at
`../hacash-fullnodedev/vm/contracts/hpay_channel_exit_v1.fitsh:196` and `:211`.
Measured on the live mainnet node 2026-08-17: its exit evidence reports
`required_action_kinds: [40, 41, 44]`, and all three are in `enabled_actions`.
**No new action numbers are needed, and none have to be un-collided.**

What is actually missing is bigger, and it is partly in this repository: the
exit contract governs a **different rail** from the mainnet money path, and the
two never meet in code.

```
mainnet money rail   POST /v1/fast-pay, native Hacash ChannelPay,
                     L1 action 2 open / action 3 cooperative close
exit-contract rail   POST /v1/hvm/payment, HvmChannelBindingV1
```

Grepping `HPAY_CHANNEL_EXIT`, `hvm_channel` and `ChannelUnilateralExit` across
`crates/l2-fast-pay-hub/src/l1_channel.rs`, `l1_channel_close.rs` and
`ledger.rs` returns **zero hits**: the native rail has no knowledge of the exit
contract. And the exit-contract rail is deliberately switched off for mainnet in
*this* repository — `crates/l2-fast-pay-hub/src/state/hvm.rs:173-177` refuses
`cosign_hvm_payment` on any mainnet profile, and
`crates/l2-fast-pay-hub/src/hvm_pilot.rs:170-174` pins the HVM pilot to chain 7.

So deploying the contract on mainnet and flipping the literal would publish
`unilateral_l1_enforceable: true` for native ChannelPay channels that the
contract does not govern — a flag naming a property the money does not have.
That is precisely what the `node_api.rs:437-441` comment exists to prevent.

The remaining work, in this order:

1. `HPAYChannelExitV1` deployed on Hacash mainnet at a height at or above
   765432, with the node re-deriving it from its own block store, and all 18
   storage leases funded and perpetually renewed (`must_renew_every_storage_key`);
2. **the expensive part, and it is in this repository** — bind the native
   funding path, bill codec, close, recovery and watchtower to that contract
   profile, and remove the three deliberate mainnet stops named above. This is a
   rail migration, not a configuration change;
3. only then flip `channel_unilateral_exit` in the fullnode, under review.

Steps 1 alone moves **no published flag**, because step 3 stays shut until step 2
lands. Deploying the contract before the rail migration spends real HAC and
starts a perpetual lease bill for zero measurable movement in the readiness
document. The readiness evaluator needs no edit, and must not be given one.

One trap worth recording, found while checking this. A contract address is
`ContractAddress::calculate(deployer, nonce 0)` — a pure function of the
deployer, independent of bytecode. The Hub's nonce-0 slot derives to
`ajsciXwwYMAWiSewt41ijKaHfAHnnm1XP`, which is exactly the registry V2 contract.
Deploying the exit contract from the Hub identity would have collided with it.
`pilot-left` is the only correct deployer, and is the one that was used.

### 2. External monotonic rollback anchor

Requirements are written up in
`docs/agent-wallet/EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md:29` and
`docs/l2/L2_SAFETY_MODEL.md:172`: a TPM or OS-keystore counter, or a remote
witness. `docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md` chose the remote
witness, because it is the only one of the three whose counter is not restored
when the Hub is.

The code exists and is on the signing path
(`crates/l2-fast-pay-hub/src/rollback_anchor/`, the witness binary
`hpay-rollback-witness` behind the `rollback-witness` feature, and the Hub side
in `src/state/rollback_anchor.rs`). What remains is **deployment**: this item
is no longer "nothing implements it", it is "no witness is configured". A Hub
with no witness configured — which is every Hub today — reads
`external_rollback_anchor_ready = false`, exactly as before, because
configuration is not evidence and the flag is a live measurement of a signed,
pinned, fresh witness answer. Wiring is
`fast-pay-hub --rollback-witness-url/-id/-receipt-address/-authorisation-address/-attestation-file`,
all five together or none; a partial anchor configuration refuses to start.
Operator procedure before it is switched on: `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`.

Who runs the witness is now decided rather than open (ADR-001, "Who runs the
witness"): the wallet user runs nothing, a Hub operator points at a witness over
the network, and moving between a shared witness, the counterparty's, a neutral
third party's or their own is a change of address rather than a change of code.
There is **no public witness address yet**, so the shipped default stays "no
witness configured" — a default pointing at a host that does not answer would be
a worse lie than an empty field. Standing up a witness:
`docs/l2/RUNNING-A-WITNESS.md`.

### 3. The flags are measurements, and nothing downstream needs an edit

`measure_l1_dispute_path_ready` weighs the node's capability block and the exit
evidence, so it turns true on its own once 1 lands.
`measure_external_rollback_anchor_ready` weighs signed, pinned, fresh witness
evidence, so it turns true on its own once 2 is configured and verified.

Both feed `HubHardGuarantees::measure`, which feeds `MainnetReadinessV1`, which
is what the Hub's money gate and both wallet gates read. No gate has to be
rewritten when either subject arrives: the wallet's channel-binding gate reads
`trustless_finality` and `unilateral_l1_enforceable` off the readiness document
and is correct in both eras by construction
(`crates/wallet-core/src/l2_hub.rs`, `require_channel_binding_guarantees`).

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

Still true on 2026-08-23, and now with a specific reason rather than a general
one. There is a finalized channel on private chain 7 holding 99000000 Zhu for its
left party with `left_claimed false`, and the V1 watchtower that owns that
channel has no claim decision to make: `decide_watchtower_action` returns
`NoAction` for chain status 4. The `ClaimLeftPayout` arm exists only on the
registry V2 rail, and the registry V2 contract deployed on that chain is not the
reviewed artifact any more. Both halves are written up under "Local Pilot
lifecycle, re-read against the running node" below.

## Local Pilot lifecycle, re-read against the running node (2026-08-23)

The section that used to stand here said `Initialization Not prepared <-- resume
here`. That is no longer where the work stops, and the sentence was misleading in
both directions. What follows was read off a live node, not off the journal.

### The node

A fullnode was built from `hacash-fullnodedev` at `app/src/version.rs` 1.0.10 and
started through `scripts/start-agent-local-pilot-node.ps1`. It is not mainnet and
proves it from its own `/query/capabilities`:

```
chain     id 7   mainnet false   height 3189 at start
network   kind local_pilot_v1   node_profile_id hpay-local-pilot-chain-v1
block 1   000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29
instance  9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3
```

The block-1 hash and the instance id are byte-for-byte the ones pinned in
`hvm_pilot.rs` as `HPAY_LOCAL_PILOT_BLOCK_ONE_HASH` and
`HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID`, so this is the same private chain the
earlier pilot ran on and not a fresh one.

### The registry V2 lifecycle cannot be resumed, for three separate reasons

1. **The sealed pilot state no longer authenticates.** `inspect` on both
   `hvm/registry-v2-pilot-state.sealed.json` and
   `hvm/registry-c3-pilot-state.sealed.json` returns
   `State("registry pilot state authentication failed")`. The state tag is an
   HMAC over `StateBody` in `hvm_registry_pilot_state.rs`, and commit `6cc0f53`
   added two fields to that struct, `refund_countersign_request` and
   `recovery_bundle_provenance`. Every state sealed before that commit therefore
   fails at HEAD. The DPAPI identities are intact: `status` on the same files
   decrypts and prints both addresses and both balances.

2. **The contract that is deployed is not the reviewed one.** The node itself
   refuses to answer for it:

   ```
   GET /query/hpay/channel-registry?contract=ajsciXwwYMAWiSewt41ijKaHfAHnnm1XP...
   {"err":"HPAY HVM registry deployment does not contain the exact reviewed artifact","ret":1}
   ```

   Deployed on chain 7: `source_sha256 58ab4ba8...`, `bytecode_sha3 276d8c20...`.
   Expected by both the node's own evidence document and
   `HPAY_REGISTRY_SOURCE_SHA256` at HEAD: `37fabe6b...` and `2fa7429d...`. That
   difference is the lease fix from `6cc0f53`, so the deployed build is the one
   whose channel keys were created with a zero recovery credit.

3. **Redeploying is a funding problem, and the number is exact.** The prefund
   step refuses with its own arithmetic:

   ```
   Error: "pilot-left balance is insufficient: mine at least 200001000000 Local Pilot Zhu"
   ```

   `HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU` is 200_000_000_000 Zhu, which is
   2000 HAC, not the 200 HAC this document used to claim. The three chain-7
   identities under DPAPI held 468.95 HAC when this was written. The block
   reward at these heights is 1 HAC (`mint/src/genesis/reward.rs`) and
   `each_block_target_time` is 455 s, so the shortfall is a fixed number of
   blocks of mining and nothing else. Mining is the only lever: difficulty is
   recomputed at validation from the same config in
   `mint/src/check/block_accept.rs`, so lowering the target time would make the
   node reject its own stored history.

Nothing here was worked around. No constant was lowered, no pin was moved and no
state was re-sealed.

### What is proven on the real node, and it is the V1 channel rail

The other HVM contract on this chain is still the reviewed artifact.
`hvm/pilot-state.sealed.json` authenticates at HEAD, and its deployment
`source_sha256 c0a430eb...` is exactly `HPAY_CHANNEL_EXIT_SOURCE_SHA256`. Reading
the blocks back gives the whole lifecycle, on the real node, with real heights:

```
2522  6a369078f214f7c6f270a732dcb5ba4c53034906d33865b4a50a83819c0714a2  deploy, contract ncJoygx8qBSHAw4sJbo5jTk1FJthJ1QLw
2530  c3e6c1c3764678d21836abe166522c51a3e8d10ac5165fd08752eac0dcc4ed9c  initialize, channel 37c817400f54d3784474191c580bfc4b
2538  6a21900f3716cd9da25fb0d6d841265c8c11900d0d6a043d69d2525be32310e2  fund, 100000000 Zhu
2549  03fe4b718f470342e6ee59c41127377c8619adc8426b3c01e95b00a955834e26  renew all 18 storage keys
2557  dbde9f0f1e02683d494819a2d553d3d55a605827f43bebe80df44d67ac564537  challenge
2566  5d58bf8837d52f276c020fe50a90151b005fa9f646c6a7f91a24a823eba430ae  respond, serial 2
2577  7a4a2fb95b0bb7e039746dec7d3bb6ba06c8d63106bc982bb499ce772837517f  finalize
```

The contract's own storage, read now through `/query/hpay/channel-exit`, agrees:
`status 4`, `serial 2`, `left_balance 99000000`, `right_balance 1000000`,
`left_claimed false`, `right_claimed false`, `all_keys_active true`.

So challenge, respond and finalize are no longer simulator-only on this rail.
The payout still is.

### The Action 14 payout has no production caller on this rail

`decide_watchtower_action` in `hvm_watchtower.rs` maps chain status 4 to
`NoAction`. There is no `ClaimLeftPayout` arm in the V1 watchtower at all; that
arm exists only in `hvm_registry_watchtower.rs`. Run against this exact channel,
the production watchtower prints:

```
Stage: watchtower no_action
Action: none
```

The V1 contract does have the payout: `PermitHAC` in
`vm/contracts/hpay_channel_exit_v1.fitsh`, guarded by `left_claimed`. So 0.99 HAC
sits settled inside a finalized channel on a real chain, while the code that
would release it lives on the other rail. Building an Action 14 by hand to move
it would be a harness, not evidence, and was not done.

### The storage lease, driven against a real node with a real clock

This was the part that had only ever been driven by mining empty MemChain
blocks. It has now been driven three times by the shipped scheduler,
`run_hvm_lease_scheduler`, against this node:

```
3314  b9dda80bc8a034ed3945302d37e76cead63267f256d4f49cd014b4cf6d3ecd7f
3532  0c5870daa3aa09f7489cf4aa96e86d5139aa3cd0e0dd8a2e4cac7c61b22a73df
3590  cf2dee77e440b1e5ac54c27898a348a18fc518b85aec8c49902a4413f9281eec
```

Each transaction carries a `Channel.renew` for all 18 key names, and the effect
is visible in the node's own snapshot: `minimum_live_blocks` went 17117, 26945,
36760, 46636, and `minimum_recover_blocks` 10000, 20000, 30000, 40000. The Hub
balance went from 6.81 HAC to 3.37 HAC across the three, so one renew-all of 18
keys for 100 periods costs about 1.15 HAC of rent on this chain, not the 0.01 HAC
network fee.

The second of the three was submitted with the miner stopped, so it sat
unconfirmed for several minutes and confirmed when mining resumed. That is the
"renewal that fails to confirm" case, and it exposed something worth writing
down.

### The scheduler renews once and then stands still until a person intervenes

Every one of the three runs went the same way. Tick one submits. Tick two, sixty
seconds later, fails closed:

```
INFO  HVM lease maintenance operation_id=hvm-lease-...-29791749 status=submitted
ERROR HVM lease maintenance channel failed closed error=state: RecoveryRequired
```

After that error the scheduler logs nothing further and does not renew again,
including in the run where the transaction had already confirmed one second after
submission. The operation was resolved only by an operator running the shipped
reconciliation command:

```
hpay-hvm-local-pilot reconcile --operation-id hvm-lease-...-29791749
Stage: exact durable reconciliation confirmed
Transaction: b9dda80bc8a034ed3945302d37e76cead63267f256d4f49cd014b4cf6d3ecd7f
Confirmations: 182
```

That reconciliation was run with the Hub process stopped, which is the one thing
here that was proven with the Hub down: the record is recoverable from the chain
alone. It is not the owner walking out with their money, and it must not be read
as that.

An unattended Hub, on this evidence, renews once and then stands still, and the
lease is the only path in this system that destroys a deposit outright. The
default `--hvm-lease-threshold-blocks` is 10000 and the recovery buffer is
months, so this is not urgent, but it is a real gap between what the scheduler is
described as doing and what it does.

### The one thing standing between here and a registry V2 lifecycle

It is 666 blocks of mining, and nothing else. Everything else was checked
against the running node rather than assumed, and every check passed:

- The deployer address is derived from the deployer, not from the bytecode, so
  redeploying from the existing Hub identity would land on the occupied
  `ajsciXwwYMAWiSewt41ijKaHfAHnnm1XP`. `preview-deploy` from a second DPAPI
  identity on this machine gives a free address,
  `avXuuLphv6YqqWjx47nuBizit1fJbxzjH`, with the reviewed
  `source_sha256 37fabe6b...` and `bytecode_sha3 2fa7429d...`.
- `preview-initialize` and `preview-fund` against that address produce complete,
  reproducible commitments offline, opening no node, identity or journal.
- A Hub bound to that second identity starts and reports
  `settlement_ready: true` on the `local-pilot` profile, so the countersignature
  `initialize` needs is available.

What is not available is the money. The prefund needs 200_001_000_000 Zhu at the
left identity, which had 1354 HAC when this was written, and the block reward is
1 HAC.

Block rate is worth writing down because it is easy to misread. A node restarted
after days of idleness mines far below the 455 s target while ASERT works off the
timestamp deficit, and that phase is finite. Measured over this session, in
order: 1.0, 2.5, 8.2 and 22.1 seconds per block, climbing toward the target as
the deficit ran out. A rate sampled during the fast phase will suggest the deploy
is twenty minutes away; it is not.

Identities and state, all under `%LOCALAPPDATA%\hpay\agent-local-pilot-v1`:

```
V1 channel rail, live and resumable today
--left-identity-dpapi-file  hvm/pilot-left.identity.dpapi          1KCRLdAATCyeEPPtYn27RpJTdLV9Ueamk
--hub-identity-dpapi-file   hub/hub.identity.dpapi                 12ZCnDaGiZW9cZhYombd4mhUNLYnXcBjq7
--state-file                hvm/pilot-state.sealed.json
--hub-state-file            hub/hub-state-hvm-pilot-3.sealed.json

registry V2 rail, waiting only on the deploy cost
--left-identity-dpapi-file  hvm/pilot-left.identity.dpapi          1KCRLdAATCyeEPPtYn27RpJTdLV9Ueamk
--hub-identity-dpapi-file   hvm/pilot-left-c3.identity.dpapi       1NS4H9casx7xY1jwF5xoB8TmVyZNE5kM9t
--state-file                hvm/registry-v4-pilot-state.sealed.json   (does not exist yet)
--hub-state-file            hub/hub-state-registry-v4.sealed.json
contract once deployed      avXuuLphv6YqqWjx47nuBizit1fJbxzjH
```

The two sealed states from the abandoned runs,
`hvm/registry-v2-pilot-state.sealed.json` and
`hvm/registry-c3-pilot-state.sealed.json`, are evidence and not inputs. They
cannot be opened at HEAD and were left exactly as found.
