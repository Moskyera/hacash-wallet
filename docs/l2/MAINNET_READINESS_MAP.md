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

The same off-by-ten-times claim was still live in the product after this
document was corrected. `hpay-hvm-registry-local-pilot`'s own `--help` described
both `preview-prefund` and `prefund-hub` as moving "200 HAC", while the constant
those commands actually drive is `HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU`, which
is 2000 HAC. Corrected 2026-08-23, with the V1 figure named alongside it so the
two are not confused again. The 200 HAC in `MAINNET_CANARY_RUNBOOK.md` is a
different constant and is correct: `HVM_PILOT_DEPLOY_PROTOCOL_COST_ZHU` is
20_000_000_000 Zhu, which really is 200 HAC. Both derive from an
`Amount::unit238` mantissa, so the arithmetic is
`mantissa * 10^(238 - 248)` HAC in each case.

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
Neither is the payout, as of 2026-08-23. What follows replaces the section that
said it had no production caller.

### The Action 14 payout now has a production caller on this rail

**Corrected 2026-08-23.** The previous version of this section was accurate when
it was written and is quoted here so the correction can be checked:

> `decide_watchtower_action` in `hvm_watchtower.rs` maps chain status 4 to
> `NoAction`. There is no `ClaimLeftPayout` arm in the V1 watchtower at all;
> that arm exists only in `hvm_registry_watchtower.rs`. Run against this exact
> channel, the production watchtower prints `Stage: watchtower no_action` and
> `Action: none`.

`decide_watchtower_action` now answers `ClaimLeftPayout` on chain status 4 when
the chain split matches the Hub's own head bill, `left_claimed` is false and
`left_balance` is positive. Behind it, `claim_left_payout_source`,
`build_signed_hvm_claim_transaction` and `read_exact_hvm_claim_transaction` in
`crates/l2-fast-pay-hub/src/hvm_watchtower.rs` build and re-read the exact Type 3
`[ChainAllow, HacFromToTrs]` payout, and
`crates/l2-fast-pay-hub/src/state/hvm_chain.rs` carries it as a durable
`HvmChainOperationKind::Claim` with its own precondition, postcondition and
Action 14 observation proof. Nothing about it is a harness: the operator command
is `hpay-hvm-local-pilot watchtower --action monitor`, exactly the command that
used to print `no_action`.

**The 0.99 HAC left this contract on 2026-08-23.** Read back from the node's own
block store, the payout built and signed by that production path:

```
block   4358  6ed3c2a0329b92c183ed7fb7fe9c8469f2da7a02034d07e6d2e5625704c6f0d6
type    3
main    12ZCnDaGiZW9cZhYombd4mhUNLYnXcBjq7   (the Hub, fee payer only)
action  1041 ChainAllow chains [7]
action  14   from ncJoygx8qBSHAw4sJbo5jTk1FJthJ1QLw
             to   1KCRLdAATCyeEPPtYn27RpJTdLV9Ueamk
             hacash 99:246                     (99000000 Zhu, 0.99 HAC)
```

The contract's own storage moved with it, read through
`/query/hpay/channel-exit`: `left_claimed` went `false` to `true` while
`left_balance` stayed at `99000000`, which is the contract recording what it paid
rather than forgetting it. The contract's HAC balance went from `1:248` (1 HAC)
to `1:246` (0.01 HAC), and `1:246` is exactly the `right_balance` the Hub has no
automated claim for. The lifecycle table above therefore gains a seventh line:

```
4358  6ed3c2a0329b92c183ed7fb7fe9c8469f2da7a02034d07e6d2e5625704c6f0d6  claim, left payout 99000000 Zhu
```

**What this payout does not prove.** The Hub could not afford the claim's
up-front gas budget at the time, so its fee wallet was topped up first with 3
HAC in transaction
`a21ba75c9d993ecac983e8eac14dc9c3077958a4bc42746caa1d6da4456df46b` at height
4356. That transfer came from `1KCRLdAATCyeEPPtYn27RpJTdLV9Ueamk`, which is the
same pilot-left identity the 0.99 HAC was then paid back to. On chain 7 every
identity here is held by one person, so the money went in a circle, and the run
therefore proves that the mechanism executes and that the contract released the
funds. It does not prove anything about an adversarial counterparty, because
there was not one. The permissionless-payout property below is read from the
protocol source rather than demonstrated by a hostile party on this chain.

Three properties are worth stating because they are what make a Hub-signed
payout safe:

- The payee is not chosen by the signer. `PermitHAC` pays `left` or `right` and
  nobody else, and `claim_left_payout_source` refuses any payee that is not
  `binding.left_address`, which `validate_runtime_binding` has already pinned to
  the contract's own `left`.
- The amount is not chosen by the signer either. `PermitHAC` demands
  `amount == left_balance` to the zhu, so the builder reads it off live contract
  storage and refuses an amount that cannot be carried exactly on the wire.
- The payout is permissionless. Action 14 declares `req_sign = [self.from]`, but
  `intrinsic_req_sign` only demands a signature from an address that
  `is_privakey()`, and a contract address is not. The Hub key pays the fee and
  has no authority over the money. When a third party claims first, the durable
  record resolves on the contract's own `left_claimed` evidence rather than
  latching recovery.

**What is still not built, said plainly.** The V1 contract's `PermitHAC` also
pays the right side, guarded by a per-channel `right_claimed`, and no shipped
code claims it. That leaves the Hub's own `right_balance` share, 1000000 Zhu on
this channel, inside the contract with no automated path out. This is a
deliberate limit, not an oversight: a watchtower exists to protect the
counterparty's principal, and an arm that pays the Hub itself is a new authority
rather than a bug fix. The watchtower prints the limit on every payout it makes:

```
Hub share still inside the contract: no automated claim on this rail; the
watchtower claims the left party's settled balance only
```

**Nobody pressed the button, and now something does. Closed 2026-08-24.** The
sentence above, "nothing about it is a harness", was true and was not enough.
The claim arm existed, it was correct, and it had moved real money, but nothing
ran it on its own. Traced on 2026-08-23:

- `run_hvm_watchtower` had exactly one caller outside the test tree,
  `crates/l2-fast-pay-hub/src/bin/hpay-hvm-local-pilot.rs`.
- That binary carries `required-features = ["local-pilot-tools"]`, the crate's
  `default` feature set is empty, and the binary's own `about` string reads
  "Fail-closed HPAY HVM lifecycle tool for the private chain-7 Local Pilot only".
- `hvm_scheduler.rs` ran three ticks on its loop: the V1 lease tick, the
  registry lease tick and the registry watchtower tick. There was no V1
  watchtower tick.

That last line was the whole gap, and it is worth being precise about what it
was not. There is no HTTP route for the V1 watchtower, but there is none for the
registry watchtower either, and that is deliberate rather than missing:
`registry_public_routes_expose_payments_but_not_owner_or_watchtower_controls` in
`server.rs` asserts that `/v2/hvm-registry/watchtower`, `activate`, `lease` and
`reconcile` are all absent from the production route table, and fails if any of
them appears. Owner and watchtower controls are deliberately not reachable over
the network on either rail. So the fix was not a route, and adding one would
break that test on purpose.

The difference between the rails was the scheduler tick and nothing else, and
that tick now exists. `HubState::hvm_watchtower_tick` in
`crates/l2-fast-pay-hub/src/state/hvm_chain.rs` evaluates every activated V1
channel once per pass, and `run_hvm_lease_scheduler` in
`crates/l2-fast-pay-hub/src/hvm_scheduler.rs` calls it on the same loop and at
the same cadence as the three ticks that were already there. It reaches the
chain only through `run_hvm_watchtower`, in the same `Monitor` mode the CLI
uses, so it can sign or submit nothing the manual path could not: it is a caller
of that path, not a second one. It never begins a challenge, which is the one
mode that spends a key on a state the chain has not yet moved to.

The feature boundary is the part that actually changed, so it is worth stating
exactly. `run_hvm_lease_scheduler` and the tick both live in the library, behind
no feature at all. The `fast-pay-hub` binary that spawns it requires `server`,
which is simply what a Hub daemon is built with. The old and only caller,
`hpay-hvm-local-pilot`, requires `local-pilot-tools`. So the claim path moved
from a private chain-7 tool a person runs by hand to the ordinary Hub daemon's
own background loop. Traced by name, with no test binary in the chain:

```
bin/fast-pay-hub.rs   tokio::spawn(run_hvm_lease_scheduler(hub, config))   [feature "server"]
hvm_scheduler.rs      run_hvm_lease_scheduler -> hub.hvm_watchtower_tick   [no feature]
state/hvm_chain.rs    HubState::hvm_watchtower_tick                        [no feature]
state/hvm_chain.rs    hvm_watchtower_channel_tick -> run_hvm_watchtower    [no feature]
```

Two properties are carried over from the lease-tick fix deliberately, because
the same wedge would otherwise appear here:

- **Outstanding work is found by binding, not by name.** The tick's own
  confirmed action changes the chain, so by the next pass the situation has
  moved on from the one that named the record. Looking for a fresh name would
  strand a signed transaction nobody is reconciling. `HvmWatchtowerSituationV1`
  gives an operation the name of the situation that called for it, so a retry of
  the same situation is the same operation and every lifecycle step earns a new
  one.
- **An operation the tick did not open is named and left alone.** An operator's
  `pilot-watch-...` record on the channel is somebody else's in-flight
  transaction. `hvm_watchtower_tick_request` refuses it by name rather than
  driving it, and refuses anything that is not a monitor action.

The `--hvm-lease-scheduler` flag's help text now says what it actually does:
leases on both rails, plus watching every activated channel so a challenge is
answered, a passed deadline is finalized, and a finalized channel's settled
principal is claimed back out of the contract. The flag name is now narrower
than the behaviour and is left alone rather than renamed, because renaming a
shipped flag breaks whatever already invokes it.

`readiness.rs` is deliberately not changed by this, and its line "nothing here
presses `finalize` or `claim` on their behalf" is still correct where it stands.
That line is part of `measure_offline_user_defended`, which is a statement about
what a *user* may rely on, and a user cannot rely on a counterparty's Hub having
been started with this flag. What changed is what a Hub operator's own process
does for the channels it holds. Those are different questions and only the
second one is answered here.

Judged against the two options this work was given, add the claim path or write
down that V1 channels have no claim path, it is now option (a) end to end: the
mechanism exists, it moved real money on chain 7, and an unattended Hub reaches
it without a person.

**The two ticks share one operation slot, and a live run is how that was
found.** A channel permits exactly one unresolved chain operation, and the lease
tick and the watchtower tick both want it. The lease tick runs first on the
loop, so whenever a renewal is in flight the tower gets nothing to do on that
channel. Two consequences, and only the second was a defect.

The first is a real limitation and is left standing: on a channel with a
renewal outstanding, a claim waits until that renewal confirms. It is
fail-closed, it is not a regression against a rail where the tower never ran at
all, and the wait is bounded by six confirmations. It is written here rather
than fixed, because giving the tower priority over a lease would trade a
delayed payout for a shortened lease, and the lease is the path this document
calls the only one that destroys a deposit outright.

The second was a defect in the first version of this tick, and running the
shipped binary against chain 7 is what exposed it. The tower reported that
ordinary deferral as a failed-closed channel:

```
ERROR HVM watchtower channel failed closed
      binding_commitment=6dfb2664f38c5805... error=state: HVM chain operation
      hvm-lease-6dfb2664f38c5805...-29792223 is unresolved on this channel and
      was not opened by the watchtower tick; the tick will not drive it
```

That line would have appeared on every pass for as long as a renewal was
outstanding, which was 29, 83 and 48 passes on the three renewals timed here. An
operator who learns to scroll past it will scroll past the one that matters,
which is the exact alarm-fatigue failure the severity work above exists to
prevent. `HvmWatchtowerPass::DeferredToLease` now names the renewal holding the
slot and reports it at `debug!`, while a record the lease tick did *not* open,
meaning somebody's hand-opened operation, stays an `error!`. Re-run on chain 7
with the fix, same channel:

```
INFO  HVM lease maintenance      operation_id=hvm-lease-6dfb2664f38c5805...-29792228 status=submitted
DEBUG HVM watchtower deferred: this channel's one operation slot is held by the
      lease renewal above  lease_operation_id=hvm-lease-6dfb2664f38c5805...-29792228
```

Pinned in `a_lease_renewal_in_flight_defers_the_watchtower_instead_of_failing_it`,
which asserts the deferral names the renewal, carries no error, broadcasts
nothing, and that the tower gets the channel back with its claim intact on the
first pass after the renewal confirms.

**What the live run did and did not show.** It showed the shipped
`fast-pay-hub`, started with `--hvm-lease-scheduler` and nothing else, calling
the V1 watchtower tick on its own loop against the running fullnode. That is the
reachability claim and it is now demonstrated rather than argued. It did not
show the tower reaching a decision on this particular channel, because this
channel's activation carries `minimum_required_recover_blocks == 0`, which makes
`lease_renewal_is_due` true on every pass regardless of the threshold flag, so
the lease tick takes the slot every time. Confirmed by running it again with
`--hvm-lease-threshold-blocks 1`, which renewed anyway. The decision paths are
covered by `hvm_watchtower_tick_claims.rs` against a mock whose mempool and
contract storage the test drives, and by the 0.99 HAC that actually left the
contract on 2026-08-23.

**The restart gate, printed by the shipped binary.** The same run demonstrated
the corrected boot message, because the first run left a submitted renewal in
its private state copy and the second refused to start:

```
Error: "HVM maintenance scheduler requires authenticated durable Hub storage, and
this state file is not settlement ready: a chain operation is outstanding and
holding the recovery latch. Run `hpay-hvm-local-pilot reconcile` against this
state file with the Hub stopped, then start again."
```

The gate is unchanged and still refuses the whole process. Only the sentence is
new, and it now names the cause and the remedy instead of neither.

**The new branch used to report the opposite of what happened.**
`decide_watchtower_action` returns `RecoveryRequired` from three unrelated
places, and the caller reported all three with one sentence: "chain serial is
newer than the authenticated HVM ledger". That is true of the original branch,
where the chain serial really is ahead. It is the reverse of the truth for the
branch this work added, a FINAL channel whose split disagrees with the head
bill, where the serial is equal and the balances differ. An operator was being
sent after a reorg that had not happened. Corrected 2026-08-23:
`recovery_required_reason` re-derives the cause from the same snapshot and head
bill the decision was made from, so a disagreeing split now names itself and
prints both sides of the disagreement. No decision changed; only what the Hub
says about it. Pinned in
`watchtower_handles_stale_challenge_deadline_unknown_serial_and_reorg_snapshot`,
which fails with the old sentence quoted back at it.

**And the case that refusal creates is now named too.** A FINAL channel whose
split disagrees with the Hub's head bill gets no automated payout at all, which
is a case the old unconditional `4 => NoAction` did not have because it never
claimed on any FINAL channel. The refusal is correct: on this one-directional
rail a chain behind the head bill pays the left party more than the Hub's own
books say it owes, and giving that away on an unexplained state is a person's
decision. What was missing was the other half of the truth, which is that the
left party is not stranded by it. The payout is permissionless, so they can
trigger it themselves at any time without the Hub, and the message says so
rather than leaving an operator to work out whether principal is at risk.

**One relaxation in the claim work bought nothing, and was removed 2026-08-24.**
`settled_elsewhere_before_signing` in `storage.rs` switched off the "lost its
exact signed transaction" requirement for a settled-elsewhere claim that had no
signed bytes, no transaction hash and no `submitted_unix`. No production path
could produce that combination: both callers of
`settle_hvm_claim_paid_elsewhere` sit downstream of points where those fields
have already been unwrapped, one behind two `ok_or_else` guards that fail with
"RecoveryRequired: HVM operation has no durable signed bytes", the other behind
a submission that sets `submitted_unix`. So the carve-out never fired for real
work and only widened what a hand-edited state file could carry past validation.
It is gone; a settled-elsewhere claim now keeps its exact signed bytes like every
other record past `SignatureMayExist`. The two remaining carve-outs, which let
such a record lack a confirmed block height and confirmations, stay: a payout
made by a third party genuinely owns no block of its own, and both are gated on
`claim_settled_elsewhere_height`, which only `settle_hvm_claim_paid_elsewhere`
can set and only after a freshly verified live snapshot has shown `status == 4`,
`left_claimed == true`, the exact amount and the exact payee. The registry
rail's identical carve-out is left alone: it has four callers rather than two,
and proving it dead is separate work.

**The durable claim path had no automated coverage at all, and that was the
weakest part of this work. Closed 2026-08-24.** Two pure functions at the two
ends were tested: the decision, in `hvm_activation.rs`, and the builder and
reader, in `hvm_watchtower.rs`. Everything between them had been exercised
exactly once, by hand, on chain 7, and nothing would have caught it if it broke.
`crates/l2-fast-pay-hub/tests/hvm_watchtower_tick_claims.rs` now runs that
middle, driving `hvm_watchtower_tick`, the function the shipped scheduler loop
calls, against a mock fullnode whose mempool and contract storage are under the
test's control:

- a FINAL channel still holding the left share is claimed, submitted once,
  resumed without rebroadcasting, confirmed against the contract's own
  `left_claimed`, and then correctly answered `no_action`;
- a permissionless third-party payout resolves the record on the contract's
  evidence instead of latching recovery over somebody else's success;
- a confirmed claim that did not move `left_claimed` paid nobody, and the
  postcondition latches recovery;
- an operator's `pilot-watch-...` record is named and left strictly alone, with
  nothing broadcast.

Each test reopens the durable state file afterwards, so `validate_hvm_state`
runs its claim rules on load and a record that only passes on write does not
survive. Red-checked twice on 2026-08-24, restoring both files by checksum
afterwards: disabling the status-4 claim arm fails all four tests with
`left: "none" right: "claim"`, and removing the resume-by-binding lookup fails
three of them, one with the verbatim `state: RecoveryRequired` that was the
lease tick's own signature.

Worth recording alongside: the third branch, `_ =>` on an unhandled chain
status, is unreachable through `decide_watchtower_action`. That function calls
`validate_runtime_binding` first, and `node.rs` refuses any status outside
`2..=4`. The arm is defensive and the test asserts the refusal rather than
pretending the arm can fire.

**Re-read live on 2026-08-23, after the payout.** Chain id 7 and
`mainnet:false` re-verified from `/query/capabilities` first. The contract state
through `/query/hpay/channel-exit`:

```
status         4          left_balance   99000000
serial         2          left_claimed   true
                          right_balance  1000000
                          right_claimed  false
contract HAC balance      1:246   (0.01 HAC)
```

Running the shipped operator command again against that state:

```
hpay-hvm-local-pilot watchtower --action monitor
Stage: watchtower no_action
Action: none
```

That `no_action` is the second claim being refused, and it is refused four times
over: the decision arm returns `NoAction` once `left_claimed` is true; the
durable precondition re-reads `left_claimed` off a live snapshot immediately
before the key is used; `validate_hvm_state` allows only one unresolved chain
operation per binding; and `PermitHAC` itself throws `HPAY_LEFT_ALREADY_CLAIMED`.
The same two words that used to be the defect are now the correct answer, which
is why the printed output alone was never evidence of anything.

### The Hub fee wallet is the real constraint, and nothing tops it up

Driving the payout on chain 7 surfaced a second thing worth writing down,
because it blocks every V1 watchtower action and not just the claim.

The node charges `tx.main` the whole gas budget up front and refunds the unused
part (`gas_initialize` in `protocol/src/context/gas.rs`), and the charge is
`budget * fee / billing_size`. At the shipped CLI default `--gas-max 255`, which
the node clamps to `TX_GAS_BUDGET_CAP_BYTE` 99 and decodes to a budget of
111911, a claim of 209 billing bytes at a 0.01 HAC fee wants 5.3545933015 HAC in
the Hub's wallet before it will run. The Hub held 3.3722580581 HAC, so the first
attempt was refused by the node at submission:

```
node: [REVERT] address 12ZCnDaGiZW9cZhYombd4mhUNLYnXcBjq7 balance
33722580581:238 is insufficient, at least 53545933015:238
```

That refusal is durable and correct, and the shipped recovery command resolves
it once the wallet can pay:

```
hpay-hvm-local-pilot reconcile --operation-id pilot-watch-4f39dab6... \
  --allow-exact-resubmit
```

The gap is that nothing in the product moves HAC to a Hub identity.
`build_hvm_pilot_exact_transfer` exists in `hvm_pilot.rs` and is `pub(crate)`,
reachable only from the registry pilot's `PrefundHub`, which sends a fixed
`HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU` and nothing else. An operator whose Hub
fee wallet runs dry has no shipped command to fill it, and a Hub with an empty
fee wallet cannot renew a lease either, which is the one path here that destroys
a deposit outright.

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

### The scheduler renewed once and then stood still, and why

This was found on chain 7 and is now fixed. The symptom, the cause and the fix
are all recorded here because the symptom is the sort that reads as a transient
and is not one.

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

An unattended Hub, on that evidence, renewed once and then stood still, and the
lease is the only path in this system that destroys a deposit outright.

**The cause was the operation's name, not the latch.** Signing a renewal moves
its durable record to `Signed` and then `Submitted`, and
`persisted_state_requires_recovery` counts both, so `refresh_recovery_gate`
raises the process-wide `recovery_required` latch the instant the transaction
exists. That latch is correct and stays: a signed transaction whose fate is
unknown must stop the Hub signing beside it, which is also why
`/v1/health` reported `settlement_ready: false` throughout. It is released by
one thing only, that same operation reaching `Confirmed`.

The only code that can carry it there is keyed to its operation id, and the id
was bucketed to a one minute clock window while the scheduler interval is at
least sixty seconds. So every pass after the first asked the clock for a name
the record did not have, found nothing to resume, fell through to
`ensure_settlement_ready`, and was refused by the latch its own submission had
raised. The confirmation that arrived one second later had nothing left
watching for it.

**The fix is that the tick looks for its own outstanding work by channel before
it asks the clock for a name.** `hvm_lease_channel_tick` and its registry twin
now resume the record they left behind, rebuilt byte for byte from the durable
copy, which reaches `run_hvm_lease_renewal`'s resume branch and through it
`ensure_hvm_chain_reconciliation_allowed`. That door already existed for exactly
this: it lets a latched Hub finish one operation, and only while that operation
is the sole reason the latch is up and the request matches the durable one
exactly. No latch is cleared on a timer, no assertion is relaxed, and no
readiness flag is set by hand. The work simply stops being hidden from the door
built to let it through.

An operation the tick did not open is named and left alone rather than adopted,
so an operator's own record still blocks the tick, and blocks it out loud:

```
channel 6dfb2664f38c5805 FAILED CLOSED: state: HVM chain operation
pilot-watch-4f39dab6... is unresolved on this channel and was not opened by the
lease tick; the tick will not drive it
```

`crates/l2-fast-pay-hub/tests/hvm_lease_tick_keeps_renewing.rs` holds the
regression across real window boundaries: three renewals, each opened in one
window and confirmed from a later one, with the latch asserted up while the
transaction is outstanding and down again once it confirms, plus the registry
twin. Reverting either half fails it on the first boundary with the original
`state: RecoveryRequired`.

**Driven on chain 7, 2026-08-23.** The tick itself, against the running
fullnode, on this same channel `6dfb2664f38c5805`, one pass per window for 59
consecutive windows. Read the next sentence before reading the trace: this run
called `hvm_lease_maintenance_tick` from a private driver, not from
`fast-pay-hub --hvm-lease-scheduler`, because the shipped binary could not boot
against a state file that was latched at the time. It is the same public entry
point the scheduler calls, but it is not the shipped process, and the
distinction matters exactly here. The shipped binary was driven separately and
that run is recorded below.

```
pass 1  window 29791914  opens hvm-lease-...-29791914  tx 6dc1f21b...  submitted
                         settlement_ready true -> false
pass 2..41                same operation resumed, 40 later windows, never refused
pass 41                   confirmed at height 4366, 6 confirmations
                         settlement_ready false -> true
pass 42 window 29791959  opens hvm-lease-...-29791959  tx 9795802e...  submitted
        (restart here)    resumed from the durable record after a process restart
                          confirmed at height 4374, 6 confirmations
pass 4  window 29791978  opens hvm-lease-...-29791978  tx 5e89d3a1...  submitted
```

Three renewals, two of them confirmed on chain and the third on the wire.
Before the fix, pass 2 was the end of it.

That trace says "restart here" and an earlier draft of this section also called
it "one unattended process". Both cannot be true and the trace is the honest
one: the process was restarted between renewal 2 and renewal 3, and renewal 3
was resumed from the durable record rather than carried in memory. Surviving a
restart is a real property and worth having; it is not the same claim as running
unattended, and the two were run together here.

**Driven again on 2026-08-23, this time by the shipped binary.** The run above
went through a private driver, so the obvious objection is that the shipped
process was never shown doing this. It has been now. Chain id 7 and
`mainnet:false` re-verified from `/query/capabilities` before the run and
throughout it. The command is the product's own, with no test hooks:

```
fast-pay-hub --listen 127.0.0.1:8796 --node-url http://127.0.0.1:8197 \
  --state-file <private copy> --identity-dpapi-file <hub identity> \
  --hvm-lease-scheduler --hvm-lease-interval-seconds 60 \
  --hvm-lease-threshold-blocks 50000 --hvm-lease-periods 1 \
  --hvm-lease-network-fee-zhu 200000 --hvm-lease-gas-max 255
```

It ran unattended for two hours and forty minutes, made 160 passes, and drove
three complete renewal cycles. The number in the operation id is the one-minute
clock bucket the operation was opened in; the whole point is that it stops
changing while a transaction is outstanding, and changes again only when the
next renewal is opened:

```
21:26:50  opens hvm-lease-...-29792006   submitted
21:27:48  same operation id              submitted   <- old code died here
   ... 27 further passes, each in a later one-minute window ...
21:54:48  same operation id              confirmed        29 windows, one operation
21:55:48  opens hvm-lease-...-29792035   submitted
   ... 82 passes, each in a later window ...
23:18:08  same operation id              confirmed        83 windows, one operation
23:19:03  opens hvm-lease-...-29792118   submitted
   ... 47 passes, each in a later window ...
00:05:47  same operation id              confirmed        48 windows, one operation
```

Three renewals, all three opened by the Hub itself and all three confirmed on
chain, from one process that nobody touched. Pass two of the first renewal is
exactly where the old code returned `state: RecoveryRequired` and stopped for
the rest of the process lifetime. Across all 160 passes the scheduler logged
zero errors and zero failed-closed channels.

`/v1/health`, sampled every twenty seconds for the whole run, changed value five
times and no more:

```
21:27:25  settlement_ready false     renewal 1 outstanding
21:54:59  settlement_ready true      released by renewal 1 confirming, nothing else
21:56:01  settlement_ready false     renewal 2 outstanding
23:18:08  settlement_ready true      released by renewal 2 confirming
23:18:50  settlement_ready false     renewal 3 outstanding
00:06:06  settlement_ready true      released by renewal 3 confirming
```

That flag does not stay true across a renewal and it must not. `settlement_ready`
is false for exactly as long as a signed transaction's fate is unknown, which is
the protection the latch exists to give. What was broken was that it went false
once and stayed false forever; what is fixed is that it comes back, every time,
on the confirmation alone. A run that showed it pinned true throughout would
mean the guard had been removed rather than that the defect had been fixed.

The three renewals reached the contract, read back from the node's own storage:
`minimum_recover_blocks` went 40400 to 40700, which is exactly three lease
periods at `--hvm-lease-periods 1`, and `minimum_live_blocks` went 46320 to
46596.

Nothing was signed or broadcast twice. The Hub's durable journal records exactly
one `hvm_chain_signed` and one `hvm_chain_submission_started` per operation,
against 29, 83 and 48 `hvm_chain_submitted` entries, which are the same record
being re-persisted at the same phase by each resume rather than new
transactions. The Hub's on-chain balance is the independent check: it moved once
per renewal, by 0.026965 HAC each time, and not at all across the resume passes
in between.

**Fixing the wedge nearly cost the alarm that reported it.** Before the fix, a
latched channel came back from the tick as a `None` result and the scheduler
logged it with `tracing::error!` as "channel failed closed". After the fix the
tick finds that operation, names it, and returns it as an ordinary response with
`status=recovery_required`, which arrived at the `Some` arm and was logged with
`tracing::info!` in exactly the shape of a healthy renewal. The wedge got harder
to reach and, in the one case where it still happens, quieter to notice. That is
a bad trade and it has been undone: `operation_needs_an_operator` in
`hvm_scheduler.rs` now reads severity off the status, so `recovery_required`
logs at `error!` on all three ticks with the consequence spelled out, and every
status the tick is legitimately carrying stays at `info!`. Pinned by
`only_the_status_an_operator_must_clear_is_logged_as_an_alert`.

**One stuck channel stops lease renewal on every other channel, and that is the
sharpest edge in this whole area.** The latch is process-wide, not per-channel.
A channel with nothing outstanding of its own takes the create path in
`run_hvm_lease_renewal`, which calls `ensure_settlement_ready()` and is refused
while any other channel holds the latch up; and the resume path is no way round
it, because `ensure_hvm_chain_reconciliation_allowed` will only drive an
operation that is the sole reason the latch is up. So a single channel whose
operation has reached `recovery_required`, and which therefore needs a human,
freezes lease maintenance for every channel the Hub serves until that human
arrives.

The guard itself is right, and it should not be relaxed: a Hub with a signed
transaction of unknown fate must not sign new money beside it. But it is worth
stating in the same breath as the sentence elsewhere in this document that calls
the storage lease "the only path here that destroys a deposit outright". The two
facts together say that one wedged channel puts every other channel's deposit on
a clock. Nothing about this changed with the tick fix, in either direction; it
was true before and it is true now. It is recorded here because a fix whose
subject is deposits destroyed by unrenewed leases should not leave it unsaid.

**Changing the threshold flag while a renewal is outstanding stops the tick, and
the error does not say so.** `hvm_lease_renewal_request` rebuilds every field of
the durable request from the durable record except one: the caller supplies
`renew_when_live_blocks_at_or_below`, and the tick supplies it from the running
config. The authenticated request commitment covers that field, which is the
point, since it is what proves a retry did not quietly change the request. The
consequence is that restarting a Hub with a different
`--hvm-lease-threshold-blocks` while an operation is still outstanding makes the
tick fail its own self-check every pass with:

```
durable HVM lease renewal request commitment is inconsistent
```

This is recoverable and it is not a permanent wedge: setting the flag back to
its previous value lets the tick resume, and `hpay-hvm-local-pilot reconcile`
works either way because it drives `reconcile_hvm_watchtower` off the durable
record and never rebuilds the request. But the message names neither the cause
nor either remedy, and nothing in the product prints the threshold the
outstanding operation was created with, so an operator has to already know this
to get out of it. The guard is right; the diagnostic is not.

**A renewal dropped from the mempool used to look healthy forever. Half fixed
2026-08-24.** The tick queries the chain for its outstanding transaction; a
transaction that is simply gone answers `Ok(None)`, which is the same answer as
"not mined yet". The pass then reported `status=submitted` at `info!`, and would
do that on every pass for the rest of the process lifetime while the lease it was
supposed to renew ran down. There was no staleness check at all: `submitted_unix`
was written in four places (`hvm_chain.rs` and `hvm_registry_chain.rs`) and the
only two reads of it were `is_none()` guards inside a claim carve-out in
`storage.rs`. Nothing compared it to a clock.

`submitted_unix` is now carried on both chain responses and read by
`submission_has_gone_quiet` in `hvm_scheduler.rs`. An operation that has been
`submitted` for at least fifteen minutes is logged at `warn!` with its
transaction hash and its age, on every one of the four tick arms, saying that
the lease or the channel is not advancing while it stands. The threshold is far
past "the next block is taking a while" on a chain that reaches six
confirmations in minutes, and well inside the window where a lease can still be
renewed by hand. Pinned in
`only_a_submission_that_has_stopped_being_ordinary_is_called_out`, which also
covers a clock that moved backwards.

This changes no decision and rebroadcasts nothing. Resubmitting signed bytes is
`reconcile --allow-exact-resubmit` and stays an operator's call, deliberately.
So the Hub now says a transaction has gone quiet; it still does not act on it,
and it still cannot tell a dropped transaction from a slow one, because the
fullnode gives the same answer for both. A block-counted staleness threshold
would be the stronger form and is not built.

The other half is untouched. An operator still cannot ask. The Hub's own channel
endpoint, `/v1/hvm/channel/{binding_commitment}`, returns the binding, the
recovery bundle and the latest signed bill, and no chain-operation state at all:
not the operation id, not the transaction hash, not how long it has been
outstanding. Confirmed live during the run below, where the transaction hash had
to be recovered from the Hub's journal file rather than from any read path the
product offers. The log line is now honest; the read path still does not carry
the question.

**Still true, and separate, and worse than "the scheduler does not start".** A
Hub restarted while an operation is outstanding does not merely skip lease
maintenance. `fast-pay-hub.rs` gates the scheduler on
`hub.health().settlement_ready`, which a latched state file makes false at boot,
and the gate is a `return Err(...)` out of `main`:

```rust
if !hub.health().settlement_ready {
    return Err("HVM maintenance scheduler requires authenticated durable Hub storage, \
                and this state file is not settlement ready: a chain operation is \
                outstanding and holding the recovery latch. Run \
                `hpay-hvm-local-pilot reconcile` against this state file with the Hub \
                stopped, then start again."
        .into());
}
```

So the entire Hub process refuses to start with `--hvm-lease-scheduler`. It does
not come up and serve payments with leases unattended; it does not come up at
all. An operator who restarts a Hub at the wrong moment gets a dead service.

The gate itself is left standing, and it is not a bug: a latched state file means
a signed transaction is outstanding whose fate nobody knows, the only way out is
`hpay-hvm-local-pilot reconcile` with the Hub stopped, and booting into a Hub
that cannot renew a lease would be the silent version of the same failure. What
was wrong was the message, which named neither the cause nor the remedy. It was
corrected on 2026-08-24 and is quoted above as it now reads.

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
