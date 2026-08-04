# How the AI Agent Wallet works

This page is for the person who owns the wallet. It explains what the AI Agent
Wallet is, what it is allowed to do, how to read its limits, and how to stop it.

Everything else in this folder is engineering documentation for the testnet
pilot. You do not need any of it to use the wallet safely.

Contents

1. [What this is](#1-what-this-is)
2. [What this is not](#2-what-this-is-not)
3. [The one rule that matters](#3-the-one-rule-that-matters)
4. [Your two wallets are separate](#4-your-two-wallets-are-separate)
5. [What the spending limits actually mean](#5-what-the-spending-limits-actually-mean)
6. [How to stop the agent](#6-how-to-stop-the-agent)
7. [What your phone can and cannot do](#7-what-your-phone-can-and-cannot-do)
8. [Reading the Activity list](#8-reading-the-activity-list)
9. [Testnet pilot status](#9-testnet-pilot-status)

## 1. What this is

An AI Agent Wallet is a separate Hacash wallet that a software agent is allowed
to ask for payments from, under limits that you set.

The agent never holds a key. It can only ask. Every payment it asks for is
built, checked against your limits, and then shown to you for a decision. If you
do not decide, nothing is sent.

Think of it as a card with a spending limit that still needs your signature on
every purchase, rather than a card you hand over.

## 2. What this is not

It is not your personal wallet. It is not connected to your personal wallet. It
does not share a key, a passphrase, or a backup with it.

It is not an automatic payment system. There is no mode in this release where a
payment is signed without an explicit decision from you.

It is not a way for an agent to hold funds. Fund it with what you are willing to
put at risk under the limits you set, and nothing more.

## 3. The one rule that matters

The Agent Wallet cannot spend anything without an explicit approval from you.

Every other control on every screen is a narrowing of that rule. The limits
decide what the agent may even ask for. Your approval decides whether it
happens. Removing the limits would still leave the approval in place.

## 4. Your two wallets are separate

My Wallet and the Agent Wallet are two different wallets with two different
keys, two different addresses, and two different passphrases.

The Agent Wallet has its own lock. Locking it does not lock My Wallet. Stopping
agent payments does not affect My Wallet in any way.

No agent, and no paired phone, can reach My Wallet. A paired phone cannot
export any key from either wallet.

## 5. What the spending limits actually mean

The two numbers on the Rules screen are stricter than their labels suggest.
Read them this way.

**Maximum per request** is checked against the total that leaves the wallet,
which is the payment amount plus the network fee. It is not checked against the
payment amount alone. A payment whose amount is just under the cap can still be
refused once the network fee is added. The wallet itself never charges a fee.

**Maximum per day** is not a calendar day. It is a rolling window of the last
24 hours, counted from the moment of the request. There is no midnight reset.

That daily figure also counts money that has not left the wallet yet. A request
sitting and waiting for your approval, and a payment that has been signed and
broadcast but not yet confirmed, both count against the daily limit while they
are outstanding. This is deliberate. It stops an agent from queueing many
requests that would collectively exceed the limit if you approved them all.

**Pending operation limit** is the number of requests one agent may have
outstanding at once, counted the same way.

One caution about the current screens. The figure labelled "Spent today" is not
the figure the daily limit is enforced against. "Spent today" counts only
completed payments, across the whole wallet. The daily limit is enforced per
agent and also counts outstanding requests. When you want to know whether an
agent is near its limit, read the limit on the Rules screen and count the
outstanding requests, rather than relying on "Spent today".

## 6. How to stop the agent

There are several controls and they do different things. In an emergency, use
the first one.

**Disable All Agent Payments**, on the desktop Overview and Security screens.
This is the real stop. It writes a durable marker before it does anything else
and invalidates any permit already issued, so it holds even if the application
is closed or crashes. New payments cannot be signed until you re-enable it, and
re-enabling can only be done locally on the unlocked desktop. No agent and no
phone can re-enable it.

The one thing no wallet can undo is a payment that has already been broadcast to
the Hacash network. Once a transaction is on the network it belongs to the
network. Stopping payments prevents everything that has not reached that point.

**Stop connector** only closes the local connection the agent talks through. It
does not disable payments. An agent that reconnects can ask again.

**Lock Agent Wallet** locks the wallet behind its passphrase. It stops work in
progress, but it is a lock, not a policy. Unlocking resumes normal operation
with payments still enabled.

**Revoke** removes an agent permanently. It cannot be undone, and it is the
right control for an agent you no longer want, not for an emergency.

## 7. What your phone can and cannot do

A paired phone is a companion. No Agent Wallet private key is ever stored on it.

The phone can see authenticated status, and in the testnet pilot it can approve
or reject one exact payment request that it has verified, using your
fingerprint. Approving signs only that one decision. It does not give the phone
a key, and it cannot sign anything else.

The phone cannot start a payment, change a limit, re-enable payments after a
stop, or reach My Wallet.

Two screens on the phone are empty on purpose. Spending rules and payment
history are never sent to a phone, so the Rules tab and the history part of the
Activity tab stay blank on every paired device. An empty history on the phone
never means that no payment was made. Read both on the desktop.

There is currently no stop control on the phone. If you need to stop the agent,
you need the desktop.

## 8. Reading the Activity list

Read the Activity list on the desktop, and read the status word on each row
rather than the row itself. A row is a record that something was attempted. It
is not proof that money moved.

A payment that your rules refused may not appear at all. A request you rejected
is removed once it expires. If you want a durable record of what an agent tried
to do, do not rely on this screen alone.

## 9. Testnet pilot status

Mobile payment approval is a testnet pilot. It accepts only an exact testnet
request with a verified network binding. It is not a mainnet feature, and this
release has no verified Agent Wallet backup or recovery path.

Do not fund an Agent Wallet with mainnet value you are not prepared to lose.
