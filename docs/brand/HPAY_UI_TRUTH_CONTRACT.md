# HPAY UI Truth Contract

The supplied black-and-gold HPAY product board is the visual direction for the
single HPAY application. It is not evidence that every illustrated protocol
capability is already available.

## Visual direction

- Use true black surfaces, restrained HPAY gold, thin borders, compact
  financial typography, and the supplied HPAY artwork.
- Use the full logo only on large brand and authentication surfaces.
- Use the approved mark-only derivative for app icons and compact headers.
- Keep HPAY product branding separate from official Hacash network and asset
  marks.
- Do not redesign the existing My Wallet flows as part of Agent Wallet work.
- Do not remove or replace the repository's Fast Pay/L2 extensions.

## Security domains

- My Wallet and AI Agent Wallet are separate wallet and permission domains.
- The Agent Wallet never receives or exposes the My Wallet private key.
- The mobile companion never contains the Agent Wallet private key.
- The local AI connector and the opt-in private-LAN mobile companion are
  separate transports and must never share a status label.

## Status labels

Every capability must be backed by real runtime state. Use these labels:

- `LIVE` for an authenticated, measured runtime state.
- `UI DEMO` only for explicitly non-production sample data.
- `NODE-GATED` for a feature disabled until the active node reports support.
- `NOT CONFIGURED` when required user or network configuration is absent.
- `REQUIRES APPROVAL` only when an actual approval path exists.
- `BLOCKED` when policy or the current release deliberately rejects the action.

Never infer `Connected` from a listener, configured endpoint, paired record, or
cached UI state.

## Current Agent Wallet release boundary

- HAC L1 is the only Agent Wallet asset path currently implemented.
- New Agent Wallet creation is testnet-only until encrypted Agent vault backup
  and restore has been independently verified.
- Existing legacy mainnet Agent vaults may be opened for compatibility, but
  funding and spending remain blocked and the UI must warn the user not to fund
  them.
- HACD, BTC on Hacash, HIP-20, providers, subscriptions, and Agent Fast Pay are
  not configured.
- The HPAY Agent Wallet fee is always zero. A payment may include only the exact
  Hacash network fee.
- Desktop approval is the only production approval mode.
- Mobile companion sync is read-only. Mobile approval, reject, emergency, and
  blockchain-signing commands are rejected server-side until secure
  anti-rollback authorization is complete.
- Mobile companion snapshots may be bounded for transport safety; the desktop
  Agent Wallet remains authoritative.

