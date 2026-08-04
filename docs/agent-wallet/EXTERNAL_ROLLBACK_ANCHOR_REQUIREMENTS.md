# HPAY External Rollback Anchor Requirements

Status: design requirement and mainnet blocker. Not implemented.

## Threat that remains

The bilateral desktop/mobile witness protocol detects rollback when one side
retains a newer authenticated high-water mark. It cannot detect a coordinated
rollback of both devices to the same older, internally consistent snapshot.
Local metadata on either device cannot solve that threat.

## Required independent property

A future mainnet design needs a third anchor outside both rollback domains. It
must provide:

- monotonic, append-only sequencing;
- authenticated binding to Agent Wallet, journal head, witness epoch, policy
  epoch, and latest final anchor;
- resistance to deletion, overwrite, equivocation, and replay;
- explicit offline/unavailable behavior that fails closed;
- privacy-preserving identifiers and no private keys, shares, signatures, raw
  transactions, or pairing secrets;
- independent restore and disaster-recovery evidence;
- a documented trust and operator model;
- external security review.

Examples may include a transparency service, independently administered
witness, or hardware monotonic counter, but none is selected or implemented.
A normal cloud backup, local file, second copy on the same desktop, or unsigned
node metadata is not an external rollback anchor.

## Current consequence

The Agent Wallet remains testnet-only and is not mainnet-ready or large-value
ready. RotationCandidate pairing improves replacement-device safety but does
not close simultaneous desktop/mobile rollback. No code may claim otherwise
until an independent anchor is implemented, audited, and physically tested.

## Local Pilot boundary

The current two-device witness pilot remains development-only. A third independent rollback anchor is still required before any mainnet security claim. Local Pilot mining and Android compilation do not satisfy that requirement.
