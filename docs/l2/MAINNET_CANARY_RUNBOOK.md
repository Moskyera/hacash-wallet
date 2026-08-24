# HPAY mainnet canary runbook

This runbook is the final live gate after the read-only infrastructure
preflight. It is not a release checklist shortcut. Any failed, missing or
ambiguous observation stops the canary and keeps mainnet signing disabled.

## Scope and safety boundary

- Use three independent accounts: Desktop Personal, Mobile Personal and Agent.
- Every account has its own private key, channel, bill store and recovery state.
- Never import or copy a Personal key into the Agent Wallet, Hub or test tools.
- Never paste a seed, private key, passphrase, DPAPI blob or signing secret into
  the report, terminal history, GitHub or chat.
- The Agent Wallet wallet fee must remain exactly zero.
- The Honor 90 must not be installed, reconfigured or modified by automation.
  Device interaction is manual and requires a separate explicit owner decision.
- Use a dedicated canary balance only. Do not use a treasury or high-value
  account.

Recommended first-canary exposure:

- 0.1 HAC per newly opened channel;
- 0.001 HAC per Fast Pay or HVM payment;
- one payment in each required direction;
- no additional funding until every earlier phase is confirmed.

These values are operational recommendations, not protocol constants. The
reviewed transaction preview remains authoritative.

## Phase 0: freeze the exact release candidate

### First, run the preflight from the app

Before you record anything, and long before any deposit, open the wallet and
run the preflight on the Fast Pay screen. Desktop: Fast Pay, under "Turn Fast
Pay ON", the button above "Enable Fast Pay". Mobile: the Fast Pay channel
screen, under Setup, the button above "Preview channel open".

You need no Rust toolchain and no terminal for this. A wallet owner has an app,
not a compiler. The button sends five read-only requests; it signs nothing,
unlocks nothing and broadcasts nothing, so it is safe to press as often as you
like.

Read the result before you go any further:

- if it says READY, that is the moment to start recording the values below,
  because you now know the node and the Hub you are about to freeze are the
  ones that answered correctly;
- if it says NOT READY, stop here. Every FATAL item has to be green before
  money goes in, and an item marked "FATAL, NOT CHECKED" counts as failed,
  because a question nobody answered is not a question that came back clean.
  Fix what the item names, or ask the Hub operator to, and run it again;
- either way, read the block titled "What this check cannot tell you, whatever
  colour it is". Green is a statement about infrastructure at one instant. It
  is not a statement that your money is safe, it does not make this pilot
  trustless, and the Hub can still refuse to countersign your voucher after
  your deposit is already in the channel.

The answer goes stale in about five minutes, so re-run it at the top of
Phase 1 rather than relying on this one.

### Then record, without secrets

1. Git commit and fullnode commit.
2. Desktop, mobile, Hub and fullnode artifact SHA-256 values.
3. Public node and Hub HTTPS origins, exactly as the preflight printed them.
4. Hub Hacash address, exactly as the Hub published it in the preflight's
   "The Hub answers, and says it can take a channel open" item. If the address
   you expected and the address the Hub published differ, that item is red and
   you are not frozen, you are misconfigured.
5. Registry rail only: HVM contract address, deployment transaction, deployment
   height and bytecode hash. On the native ChannelPay rail there is no
   contract, so there is nothing to record here.
6. Public addresses for Desktop Personal, Mobile Personal and Agent.
7. The preflight verdict and the per-item results, saved with the report.

Do not continue if the source or any artifact changes after this point. A
change requires a new preflight and a new canary report.

## Phase 1: read-only infrastructure proof

Two rails, two preflights. Run the one for the rail you are actually on.

### If you are on the native ChannelPay rail with a close voucher

This is the rail with no HVM contract: a channel opened as
`[ChainAllow 0x0411, ChannelOpen 2]` plus one Hub-countersigned delta-zero
voucher `[ChainAllow 0x0411, ChannelClose 3]`, taken once and never refreshed.

Run the preflight from the wallet itself, on the Fast Pay screen, before the
deposit. It is the `wallet_native_rail_preflight` command and needs no Rust
toolchain, because a wallet owner has an app and not a compiler.

Required result:

- every FATAL item shows PASS. A skipped item is not a passed item, and the
  screen will not show READY while any fatal item failed or could not be run;
- the Hub voucher item is green. It reads a different flag set from the open
  (`official_channelpay_ready`, `close_enabled`, an empty `close_blockers`),
  and a Hub can be green for the open and red for the close;
- the close-voucher route probe is green. Nothing the Hub publishes declares
  this route: API version is 7 with or without it. A 404 means an older Hub,
  and funding it strands you, because the voucher can only be taken after the
  deposit is already on chain.

A green result is authority for at most 330 seconds and it never means the
money is safe, that the pilot is trustless, or that the Hub will countersign
when asked. The screen lists what it cannot check; do not treat any of it as
proven.

### If you are on the HVM shared-registry rail

Only if the registry contract is actually deployed. It costs on the order of
2000 HAC, and this preflight cannot pass without a verified deployment.

```text
cargo run -p hacash-wallet-core --example hpay_mainnet_infrastructure_preflight -- --node-url https://NODE --hub-url https://HUB --hub-address HUB_HACASH_ADDRESS --payment 0.001 --channel-funding 0.1
```

Required result:

- `status` is `pass`;
- `scope` is `read_only_infrastructure_only`;
- canonical mainnet block 1 and network instance are present;
- bound submit is true;
- Hub API is version 7 or newer;
- wallet fee is exactly zero;
- HVM deployment is independently verified with the reviewed bytecode;
- the result still says `release_ready: false`.

Save the complete JSON and its SHA-256. Do not edit it.

## Phase 2: Personal channel setup

For Desktop Personal and Mobile Personal separately:

1. Review the exact node URL, Hub URL, Hub address and 0.1 HAC deposit.
2. Confirm that the transaction contains only the exact ChainAllow and channel
   open actions, with no treasury or wallet-fee transfer.
3. Sign through the normal owner ceremony.
4. Record the L1 transaction hash and channel ID.
5. Wait for the wallet to prove at least six confirmations.
6. Restart the corresponding application and confirm that the same channel,
   reuse version, open height and balance are recovered.

Stop if an application offers to open a second channel, changes an identifier,
or reports ready before six confirmations.

## Phase 2b: take the close voucher, before paying anything

This phase did not exist when this runbook was written, because the voucher did
not exist. It belongs here and nowhere else: **after the open confirms and
before the first payment.** Doing it in this order is what turns the deposit
from a hostage into something you can recover alone.

Why. Hacash has no unilateral close. `channel_close` requires both signatures
and there is no challenge action, so a channel normally opens only if the Hub
later agrees to close it. A voucher is one close the Hub has already signed and
handed to you. Nothing binds it to a submitter and nothing expires it, so you
can broadcast it yourself, at any future height, with the Hub gone.

For each channel opened in Phase 2:

1. Take the voucher as soon as the wallet reports six confirmations. Do not
   make a payment first.
2. Confirm the wallet accepted it. It verifies the bytes itself and must not be
   trusted on the Hub's word: exactly two actions `[ChainAllow, ChannelClose]`,
   no principal transfer present, the right chain, the right channel, you as the
   fee payer, the bytes hashing to the claimed hash, exactly two signatures, and
   both verified against your address and the Hub's.
3. Record the voucher transaction hash and the SHA-256 of the exact bytes.
4. Confirm the channel is **still open and still payable**. A voucher must not
   freeze it. If the channel went unusable, stop: something took the
   cooperative close path instead.
5. Back the wallet up, restore it into a separate empty store, and confirm the
   restored wallet holds the same hash and the same bytes. A voucher that does
   not survive a restore is not an exit.

Stop conditions for this phase, all of them final:

- The Hub refuses to countersign. Do not make any payment. The deposit is only
  recoverable with the Hub's cooperation until a voucher exists, so treat a
  refusal or a silence here as an incident and close cooperatively while the Hub
  is still answering.
- The Hub offers a second voucher for the same channel. Exactly one may ever
  exist. A Hub that issues two is not running this build and must not be funded.
- The Hub issues a voucher that carries a transfer, or issues one after a
  payment. Both are refused by a correct Hub and by the wallet.

The trust, undressed, because this phase is where it is decided. The Hub must
sign once and nothing in Hacash can compel it. There is a real window between
the open confirming and the voucher arriving in which the deposit depends
entirely on the Hub, and this runbook cannot remove that window, only keep it
to minutes. After the voucher exists the exposure moves onto the Hub: you can
spend the channel down and still recover the balance recorded at open. That is
acceptable only while you run the Hub yourself. It stops being acceptable the
moment the Hub belongs to somebody else.

Evidence that this works on a real chain, with the Hub killed and the wallet
restored from backup, is in `docs/l2/CHAIN7-CLOSE-VOUCHER-EXIT.md`. That was
chain 7, not mainnet.

## Phase 3: Personal Fast Pay in both directions

Execute exactly:

1. Desktop Personal to Mobile Personal: 0.001 HAC.
2. Mobile Personal to Desktop Personal: 0.001 HAC.

For each payment record:

- operation ID and payment ID;
- payer and payee channel IDs;
- amount and exact zero Hub and wallet fees;
- bill serial before and after;
- payer debit and recipient credit;
- recipient confirmation for a routed payment;
- final status after both applications restart.

Retry the final status query with the same IDs. It must return the same result
and must not create another debit, bill or L1 transaction.

## Phase 4: Agent Fast Pay

1. Confirm that the Agent address differs from both Personal addresses.
2. Open and confirm an Agent-only 0.1 HAC channel.
3. Create an approval for exactly one 0.001 HAC payment to the allowlisted
   canary recipient.
4. Verify the approval commitment, expiry, policy epoch, signer epoch,
   emergency epoch, Hub identity and channel incarnation.
5. Execute once and record the resulting bill and payment IDs.
6. Confirm wallet fee zero and total debit exactly 0.001 HAC.
7. Restart the Agent service and reconcile using the same durable IDs.
8. Verify that no Personal bill store, channel, history or signing session was
   opened or modified.

Pressing Pause All Agents at any point before submission must prevent new key
use. An uncertain outcome must stay RecoveryRequired and must never fall back
to L1 or create new IDs.

## Phase 5: HVM lifecycle canary

Hard blocker: do not execute this phase with `HPAYChannelExitV1` on mainnet.
The reviewed v1 contract stores one fixed channel per deployment, and its
Action 40 protocol cost is `20,000,000,000` Zhu (200 HAC) before the network
fee. That is not a low-value canary and must never be inferred from the 0.1 HAC
channel deposit recommendation above.

This phase remains blocked until either an independently audited shared
multi-channel contract amortizes the deployment cost without changing Hacash
consensus, or the owner separately authorizes and funds the exact 200 HAC plus
fee exposure after an external audit. Removing the gate, lowering only a UI
limit, or reusing a Local Pilot deployment is not an acceptable workaround.

After that prerequisite is met, use a new, separate low-value HVM channel. Do
not reuse any channel from the previous phases.

1. Re-query and verify the deployed contract code and deployment transaction.
2. Initialize with exact left, contract and Hub participants and ReqSignList.
3. Fund exactly 0.1 HAC from the canary owner and zero HAC from the Hub.
4. Verify all 18 storage keys and activate the durable recovery binding.
5. Renew every lease and prove positive live and recovery credit for all 18
   keys.
6. Execute one fee-free 0.001 HAC payment and persist the exact signed bill.
7. Submit a stale prior bill as the controlled challenge.
8. Confirm that the production watchtower responds with the latest bill.
9. After the deadline, finalize and prove the final serial and balances match
   the latest signed bill.
10. Restart the Hub between observations and verify exact recovery without a
    second signature or duplicate submission.

Any lease, balance, serial, contract hash, challenge deadline or network
identity mismatch is a hard failure.

## Phase 6: cooperative L1 close

If a cooperative close cannot be obtained, the Phase 2b voucher is the
fallback and needs nothing from the Hub. Broadcast it through your own node.
It pays you the balance recorded at open, so any amount already spent through
the channel comes back to you and the Hub loses what it earned. Record that as
an incident rather than a clean close.


Close the Desktop Personal, Mobile Personal and Agent channels one at a time.

1. Load the latest fully signed local bill from the correct account scope.
2. Review exact final balances and network fee.
3. Require the same node identity and Hub identity used during setup.
4. Submit the cooperative close and record its transaction hash.
5. Wait for canonical confirmation and restart the application.
6. Verify the channel is closed, no new payment can start, and retained history
   remains authenticated and readable.

Never close using the original deposit when the latest signed L2 balances have
changed.

## Mandatory stop conditions

Stop immediately and preserve all state when any of these occurs:

- node or Hub TLS, identity, freshness or capability changes;
- readiness expires or contains any blocker;
- nonzero Hub or Agent wallet fee;
- unexpected action, recipient, amount, channel or transaction hash;
- missing six-confirmation proof;
- bill serial gap, repeated debit or changed retry bytes;
- signature may exist but exact bytes are unavailable;
- emergency epoch changes;
- Hub, node or wallet cannot reconcile after restart;
- HVM code, deployment evidence, lease or runtime state differs;
- Personal and Agent state directories overlap;
- any request to disable a fail-closed check to continue.

## Release decision

Release is allowed only when every phase has complete evidence, every final
balance reconciles, all channels are closed or intentionally retained with a
documented recovery plan, and the complete CI-equivalent suite passes again on
the frozen source. Infrastructure preflight alone is never release approval.

If the canary fails, do not delete journals, regenerate IDs, re-sign, change
node endpoints or retry with a larger amount. Preserve the exact state and
investigate the first failed invariant.
