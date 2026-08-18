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

### Decided: disclosure and a bounded amount

The owner chose B on 2026-08-19. Both halves are done.

The cap needed no change: it was already 10 HAC per channel. It had been
reported here as a thousand, which was a unit error - `parse_amount_mei` returns
millimeis and the conversion multiplies by 100,000, so one HAC is 100,000,000
zhu. A test caught it.

The consent now reads:

> "I understand that this provider holds my channel funds. If it stops
> answering, or if it puts an old receipt on chain while I am offline, I could
> lose part or all of what is in this channel. At most 10 HAC per channel is at
> risk. I will not put in more than I can afford to lose."

Both failures named, then the number, then the sentence that matters. The
sleeping-user risk is in it deliberately: it is the one the cap is actually for,
and a disclosure that omits the failure it bounds is not the choice that was
made. The string exists in two places - the screen shows one, the backend
compares the other byte for byte - and they are checked identical.

A watchtower remains available to whoever wants to run one, and is not a
guarantee this promises.

---

## Decision 2 — lifting the exit brake

### The situation

`USER_SIDE_UNILATERAL_EXIT_DRIVER_READY` in
`crates/l2-fast-pay-hub/src/readiness.rs` is `false`. It is read in exactly one
place in shipped code, and it is what makes the exit control refuse.

Setting it true does not mark a milestone. It makes a real-money button live in
the desktop builds that ship.

### The circularity, and how it was broken

This used to be undecidable by measurement. The command refused unless the flag
was true, and the flag was what a proving run through the command was meant to
justify, so the three lines that sign had executed in no build, ever.

That is no longer the case. The command is two functions now: one asks whether
it may, one does the work. The shipped path still refuses first and nothing
sets the constant — but a test can drive the second half without pretending the
first said yes, and it has:

    challenge  confirmed at height 765436
    finalize   confirmed at height 765444
    claim      confirmed at height 765445
    outcome complete, 5,000,000,000 zhu claimed, provider process dead

Two presses, because one press drives as far as the chain allows and stops at
the objection window the contract publishes. Waiting it out and pressing again
is what an owner does.

The ordering guard was rewritten stricter rather than weakened: it pins the
gate before the hand-off, and that the driver has exactly one caller in shipped
source — which nothing asserted while the two were joined.

The measured half of the gate already reads **true**. The constant is the only
unmet term, and it is now the only thing between a proven mechanism and a
person being able to reach it.

### What two independent reviewers said

Both: **not yet**, and both called it the closest it has been. Their reasons
differed, and the second is the one to act on:

* the first found the exit path itself sound and could not fault it;
* the second found the guard that holds the test-only seam had three
  demonstrated blind spots while reporting green. Those are closed now. Two
  narrower ones remain and are recorded as known limits, both requiring write
  access to the repository — a different threat, with cheaper routes.

### What it now rests on

The run has happened, so the question has changed shape. It was "open it to find
out whether it works", which asked you to take a risk in order to learn
something. It is now "open it for users", which is an ordinary product decision
with the evidence already in front of it.

What is still true and worth weighing:

* the exit is proven against a chain with the provider deleted, entered from the
  command's own body, and it survives the app closing mid-sequence;
* the consent now names both failures - the provider that stops answering, which
  the exit answers, and the old receipt settled while the owner sleeps, which it
  does not - and names the amount;
* the cap is 10 HAC per channel, enforced by the wallet independently of
  anything the provider claims;
* what has never run is a release binary doing this against Hacash mainnet,
  because the contract is not deployed there. Deploying is the separate
  three-step matter below.

Do the run first, then the flag. The run is done.

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
