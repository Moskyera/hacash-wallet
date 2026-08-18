# The two decisions before mainnet

Everything else on the unilateral exit is work, and work has an end. These two
do not: no amount of engineering answers them, because they are choices about
what to promise users. This file states them, with the evidence measured for
each, so they can be decided without re-deriving anything.

Written 2026-08-18, after the exit was driven to completion on a real chain.

---

## What is already true

Do not re-litigate these. Each was driven on a chain, through production code,
not argued.

**A user gets their money back when the provider is gone.** A wallet opened a
channel, funded it 5,000,000,000 zhu, paid through it, the provider process was
deleted and its socket asserted dead, and the wallet walked the whole exit alone
with its own key: 4,969,317,395 zhu returned, the contract left holding zero.

**The exit survives the app closing.** Killed twice mid-sequence, it resumes
against the same transaction rather than signing a second one, and a confirmed
payout can never be signed again.

**The payout cannot be redirected.** `PermitHAC` pins the destination to the
channel's left party and the amount to `c_left_balance_` to the zhu. Two attempts
by the provider errored; a stranger then completed the exit and the coin landed
on the user.

**The contract no longer destroys deposits on a timer.** It refuses to take coin
it cannot promise to keep reachable, and a lapsed lease is dormant and restorable
by anyone rather than deleted.

---

## Decision 1 — the user who is asleep

### The situation

A provider can put an **old** receipt on chain, one that pays the user less than
they are owed, at the moment the user is offline. There is a fixed window to
answer with the correct receipt. If nobody answers, the old split settles.

Measured: on a channel owing the user 900,000 zhu, 300,000 settled to the
provider instead.

This is not a bug in this system. It is the shape of every payment channel, and
Lightning has not solved it elegantly after years.

### The only two answers found

Thirteen scenarios were driven on a real chain looking for a third. There isn't
one.

**A. Somebody watches.** Either the user runs something continuously, or a third
party watches on their behalf. A response watcher exists and works. The cost is
that an ordinary user will not run a daemon, and a third party is another party
to trust — and one built for this was measured *taking* money from the user it
was meant to protect before that was fixed.

**B. It is disclosed and the amount is capped.** The user is told plainly what
they risk and the cap keeps it small. Today the wallet-enforced hard cap is
1,000,000,000 zhu — a thousand HAC — per channel, which is a large amount to lose
while asleep.

These are not exclusive. B protects everyone immediately; A protects the users
who will do it.

### What is recommended

Do both, in this order. Lower the cap first — it is one constant, enforced by the
wallet so a lying provider cannot raise it, and it bounds the loss for every user
today. Then offer the watcher to those who want it, with its posture stated
honestly rather than as a guarantee.

The consent text needs to change either way. It currently reads:

> "I understand Agent Fast Pay mainnet is a trusted bounded pilot and I accept
> its recovery limits."

That is technically true and practically opaque. It does not say how much is at
risk, and it does not say that "trusted" means the provider can keep the money.

---

## Decision 2 — lifting the exit brake

### The situation

`USER_SIDE_UNILATERAL_EXIT_DRIVER_READY` in
`crates/l2-fast-pay-hub/src/readiness.rs` is `false`. It is read in exactly one
place in shipped code, and it is what makes the exit control refuse.

Setting it true does not mark a milestone. It makes a real-money button live in
the desktop builds that ship.

### Why it cannot be decided by measurement alone

The exit command refuses unless the flag is true, and the flag is what a proving
run through that command is meant to justify. So three lines — the chain view,
the first driver pass and the pass budget — have never executed from their own
call site, and no test can reach them while the flag is down.

Everything up to the gate has run on a real chain with the provider dead. The
gate itself executed and refused correctly. The measured half of the gate — the
probe that drives the real builders with a real non-Hub key — already reads
**true**. The constant is the only unmet term.

### What two independent reviewers said

Both: **not yet**, and both called it the closest it has been. Their reasons
differed, and the second is the one to act on:

* the first found the exit path itself sound and could not fault it;
* the second found the guard that holds the test-only seam had three
  demonstrated blind spots while reporting green. Those are closed now. Two
  narrower ones remain and are recorded as known limits, both requiring write
  access to the repository — a different threat, with cheaper routes.

### What would earn it

One run entering at the Tauri command that ends with the owner paid on chain.
That needs the gate open while it runs, which is the circularity above. It is a
deliberate act by a person: open it, run it, and either keep it open because the
run passed or close it because it did not.

Do the run first, then the flag. Four rounds of this file have now been the other
way round.

---

## What does not need a decision

* **Lease renewal driven against a real node.** The one path that destroys a
  deposit outright. The driver renews before it will start an exit and must renew
  the half that is short — the six shared globals and the twelve channel keys are
  separate calls, and renewing the wrong one is a fee spent to stand still. This
  is work, not a choice.

* **Deploying the contract to mainnet.** Three steps, not one. Deploying alone
  moves nothing: the readiness document does not change until the manifest names
  the real address and the node re-derives the deployment from its own block
  store. Doing it before the exit is reachable buys a contract nobody can use.
