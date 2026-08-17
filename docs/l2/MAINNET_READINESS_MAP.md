# What full mainnet actually requires

Written 2026-08-15. Re-measured 2026-08-17 against the real Hacash mainnet
fullnode, from the running system and the code, not from the plan.

Every claim here was verified by reading the source or querying a live Hub and
node. Where something is an inference it says so.

## The authority is the Hub, not this document

`GET /v1/readiness/mainnet` on a running Hub is the machine-readable answer.
It is evaluated by `MainnetReadinessV1::evaluate`
(`crates/l2-fast-pay-hub/src/readiness.rs:193-360`). Ask it rather than trusting
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
                         fullnode_does_not_report_verified_channel_unilateral_exit
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
  fullnode_does_not_report_verified_channel_unilateral_exit
close_blockers  []
```

`close_blockers` is empty on both, so cooperative close is available on both
profiles even while the full profile refuses payments (`readiness.rs:280-293`
filters the waived and admission identifiers out of `blockers`).

Two identifiers that look like blockers and are not. The control, the same two
profiles pointed at the pilot node on 8197 instead:

```
mainnet-pilot          blockers  external_monotonic_rollback_anchor_is_not_ready
                                 unilateral_l1_dispute_path_is_not_ready
                                 mainnet_pilot_requires_hacash_mainnet_fullnode
                                 fullnode_below_pinned_mainnet_checkpoint_765432
                                 fullnode_does_not_report_verified_channel_unilateral_exit
mainnet-bounded-pilot  blockers  mainnet_pilot_requires_hacash_mainnet_fullnode
                                 fullnode_below_pinned_mainnet_checkpoint_765432
```

`mainnet_pilot_requires_hacash_mainnet_fullnode` (`readiness.rs:234-236`) and
`fullnode_below_pinned_mainnet_checkpoint_765432` (`readiness.rs:237-242`) are
artefacts of pointing a mainnet profile at the wrong chain. They vanish against
the real mainnet node, as the two documents above show, and are not work.

## Two mainnet routes exist, and they are not the same thing

`readiness.rs:207-213` branches on `is_bounded_pilot`:

```rust
let is_bounded_pilot = profile == MAINNET_BOUNDED_PILOT_PROFILE;
if !external_rollback_anchor_ready && !is_bounded_pilot { blockers.push(...) }
if !l1_dispute_path_ready && !is_bounded_pilot { blockers.push(...) }
```

and on the profile again at `readiness.rs:250-262`, which raises
`fullnode_does_not_report_verified_channel_unilateral_exit` on `mainnet-pilot`
only.

**Bounded pilot** waives those three blockers and nothing else. It is the route
the code is built to reach today, and has reached: mainnet with deliberately
bounded exposure. Everything else the full profile demands is demanded of the
bounded profile identically:

| demand | where |
| --- | --- |
| Hub signer plus authenticated durable storage | `readiness.rs:204-206` |
| payment and channel-funding caps inside their compile-time ceilings | `readiness.rs:215-229`, `readiness.rs:679-685` |
| the fullnode reports mainnet, at or above height 765432 | `readiness.rs:233-242` |
| action 2 channel open and action 3 cooperative close enabled | `readiness.rs:243-249` |
| a configured user allowlist and aggregate TVL inside its cap | `readiness.rs:568-601` |
| a zero wallet fee, re-checked at the signing boundary | `readiness.rs:654-676` |

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

`MainnetReadinessV1::evaluate` (`crates/l2-fast-pay-hub/src/readiness.rs:352-353`)
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
aggregate measurement (`readiness.rs:803-809`); it is simply no longer exported
on the liveness endpoint.

### 1. Unilateral L1 dispute path

**Corrected twice. Read the dates.** The 2026-08-15 version said the contract
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
