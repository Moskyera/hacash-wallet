# Agent Wallet: what is left

Written 2026-08-05, after the week that made pairing work and closed eight traps.
Ordered by what blocks what, not by size.

## In flight

**Anchor expiry in every witness phase.** The first phase is fixed and proven safe by
re-issue. The post-submit phase has the identical five minute lifetime and no exit,
and post-submit means the money has already gone to the network. A running pass is
enumerating every phase rather than patching the one that was reported, because this
defect has now appeared twice in exactly that shape.

## 1. Before anything can hold real value

These are not features. Nothing else matters until they are done.

**A payment on real hardware.** Every proof so far used a mock Local Pilot node. Not
one payment has ever completed on a real device against a real node, not even on
testnet. This week found eight defects that passed every test and failed when run, so
"the tests are green" is not evidence. Needs the miner started, which is the owner's
decision.

**Witness baseline on real hardware.** Never initialized. The journal has no witness
or approval event in 46 records.

**Backup and recovery.** Built, on the owner's decision: restore everything, exactly
as the Personal Wallet does, and warn. It is a STATE backup of four mutually
consistent files - `registry.json`, `wallets/<id>/vault.json`, the journal and the
wallet state - sealed with the wallet's own Argon2id and AES-256-GCM, and a restore
refuses outright if those four disagree. See `crates/agent-wallet-core/src/service/backup.rs`.

A restore is also one TRANSACTION, which it was not when it was first written. The five
durable writes used to publish the registry entry last and call that enough; a crash
between the vault write and the journal write left the keys on disk under a wallet the
registry did not list, and the restore's own pre-check then refused it for ever, to the
retry and to a retry after a reboot alike. `begin_wallet_restore` now records which
wallet is being built before any of it reaches disk, the registry entry is the commit
point, and `recover_interrupted_wallet_restore` runs at every `AgentWalletManager::open`
and again at the top of every restore. Every one of the eight windows is crashed at in
`crates/agent-wallet-core/src/service/companion/tests/restore_atomicity.rs`, and after
the next open the store holds either the whole wallet or no trace of it.

A restore IS a rollback, and the four consequences are executed in
`crates/agent-wallet-core/src/service/companion/tests/state_backup.rs`: the spend
window returns to the backup point, a revoked agent comes back live with its
allowance reset, the old witness phone answers `RollbackDetected` for ever and must
be replaced by a lost-phone rotation, and the backup file plus its passphrase is a
second working wallet that can spend at the same time as the first. All four are
shown and must be ticked before either flow will run. Mainnet remains blocked, and
not because of this.

**Independent security review.** Nobody outside this work has read it.

## 2. The product the owner actually described

The owner's scenario: at home, ask the assistant to find a dev, it says 50 HAC, they
say yes, the payment happens.

**Agent Wallet on L2.** This was the original intent. It was excluded from the pilot
so the pilot could not disturb Personal Wallet L2, and then it stayed excluded. The
hub exists and works for the Personal Wallet; it is not wired to the agent. On L1 the
50 HAC payment carries a fee and a confirmation wait that the design was meant to
avoid.

**Amount threshold.** Small payments proceed, large ones ask. It was built once and
reverted because an automatic payment stranded with no phone prompted. The witness
discovery work removed that reason, so it can be attempted again. It is also the
prerequisite for the two below: without a threshold, notifications have nothing to
announce and an unattended runtime has no filter.

**Push notifications to the phone.** Must not use the companion LAN transport, which
is private-Wi-Fi only by design and cannot reach a phone that has left the house.

**A runtime that survives without the UI open.** Today the desktop must stay open and
unlocked, and switching to My Wallet locks the Agent Wallet. An agent that only works
while someone watches a screen is not an agent.

## 3. Known defects, small

**Policy migration.** An agent whose stored policy uses a mobile approval mode cannot
be migrated in place; the only route is a permanent revoke and re-pair.

**Double press dropped silently.** A second tap inside the same React tick returns
early with no message. The buttons disable a tick later, so it is close to theoretical.

**recipientStanding is permanently "unverified".** The desktop sends an empty policy
list to every phone by design, so the phone can never verify a recipient. The wording
is honest but reads as a per-request fault rather than a permanent design fact.

## 4. Housekeeping

**Commit the work since 2e058d1.** Around 74 files are untracked again: witness
discovery, the four dead ends, the trap sweep, anchor recovery. The baseline commit
exists precisely so this does not sit outside git.

**Close the desktop debug port.** The desktop is running with
`--remote-debugging-port=9223`, opened so the agent could operate it. It must be
started normally for ordinary use.

## What this week established about method

Eight defects were found. Every one of them passed the existing tests. Every one was
caught by executing a flow rather than reading it, and four were caught only because
a pass was told to stop rather than deliver something unsafe.

The recurring shape: two sides each individually correct, disagreeing about a contract
nobody had written down. A random counter read as a monotonic one. Sixty seconds of
clock tolerance on one side and zero on the other. A registry that treated re-pairing
as forbidden while the phone deliberately kept its identity. None were bugs in the
narrow sense.

The other recurring shape, twice: a fix that closed a defect at one point and left it
at the next.
