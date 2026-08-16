# HPAY Fast Pay Hub Operator Guide

This guide is for operators running the official Hacash ChannelPay-compatible HPAY Fast Pay Hub. End users only need HPAY Wallet.

## Mainnet safety profiles

HPAY has two separate mainnet profiles. `mainnet-pilot` is the fail-closed trustless profile and remains unavailable until an independent rollback anchor and unilateral L1 dispute path exist. `mainnet-bounded-pilot` is an explicit trusted-Hub pilot. It uses official Hacash ChannelPay bill documents and does not change Hacash consensus, but it is Hub coordinated and is not trustless or unilaterally enforceable on L1. The active Hacash mainnet exposes cooperative original-funding close action 3, so an operator and user must cooperate to settle a channel on L1.

**Current release status:** the one-click installer selects `mainnet-bounded-pilot`. It can enable new channel funding and payment signing only for explicitly allowlisted users, only while every readiness check is green, and only inside the hard 1/10/100 HAC limits. Wallets remain opted out by default and must display and persist the user's explicit trusted-pilot consent. The trustless `mainnet-pilot` profile still reports the missing rollback/dispute blockers and keeps `payments_enabled=false`.

The Hub fails closed unless all of the following remain true:

- a compatible HPAY full node reports fresh mainnet capabilities;
- the full node is at or above the pinned mainnet checkpoint;
- the Hub signer, durable state and authenticated journal are configured;
- the selected profile is exactly the policy explicitly accepted by the wallet;
- for `mainnet-pilot`, an independent rollback anchor and unilateral L1 dispute path are verified, and the exact full node reports `features.channel_unilateral_exit=true`;
- for `mainnet-bounded-pilot`, the payer is allowlisted and aggregate Hub TVL stays within its cap;
- the wallet fee is exactly zero;
- both the payment and channel-funding amounts stay within their configured caps;
- readiness is rechecked immediately before every Hub signature.

Normal HPAY Wallet L1 sends do not depend on this Hub and keep working when Fast Pay is unavailable.

## Components

| Piece | Binary | Role |
|-------|--------|------|
| Fast Pay Hub | `fast-pay-hub` | Wallet Hub API v7 and short-lived mainnet readiness |
| HPAY full node | `hacash` / `hacash.exe` | Hacash L1 plus `/query/capabilities` |
| Hub wallet | Separate Hacash keypair | Signs only the Hub side of ChannelPay bills |

## Prerequisites

1. A fully synchronized HPAY-compatible Hacash full node, normally at `http://127.0.0.1:8080`.
2. A dedicated Hub wallet funded only with the liquidity required for the pilot.
3. A persistent data directory on local encrypted storage.
4. HTTPS termination in front of the Hub. Never expose the internal HTTP port directly to the internet.
5. Open user-to-Hub channels. Either channel side is supported.

## Secrets

Create and store three required independent values outside the source tree, plus an optional full-node API token:

- `HACASH_HUB_ADDRESS`: Hub Hacash address.
- `HACASH_HUB_SECRET_HEX`: 64-character private key matching the Hub address.
- HACASH_HUB_JOURNAL_KEY_HEX: independent random 32-byte key encoded as 64 hex characters.
- HACASH_HUB_STATE_KEY_HEX: a second independent random 32-byte key used only to seal the complete durable state container.
- `HACASH_NODE_API_TOKEN`: optional token matching the full node configuration. Required when the full node protects its API with a token.

All three secret keys must be different. Never commit these values, upload them to a GitHub repository, include them in an image, or reuse one key for another purpose. Use the operating-system secret manager or a root-owned environment file with the narrowest possible permissions.

## Build

```bash
cargo build -p l2-fast-pay-hub --features server --bin fast-pay-hub --release --locked
```

## One-click Linux VPS package

A `vX.Y.Z-hub` tag builds `hpay-fast-pay-hub-vX.Y.Z-linux-x64.tar.gz` through `.github/workflows/release-hub.yml`. The release contains the compiled binary, installer, hardened systemd unit and operator README. Verify the published SHA-256 file and GitHub provenance, extract the archive, then run `sudo ./install.sh`.

The installer verifies the local HPAY full node, creates independent journal and sealed-state keys, installs a dedicated service account and binds the Hub only to loopback. It refuses to overwrite an existing signer, journal key, state key or state. HTTPS reverse-proxy setup remains an explicit operator step because it requires the operator's own domain and certificate.

## Bounded mainnet pilot run

The bounded mainnet pilot caps each payment at 1 HAC (`100000000` Zhu), each newly funded channel at 10 HAC (`1000000000` Zhu), and aggregate active/reserved Hub TVL at 100 HAC (`10000000000` Zhu). Operators may configure lower values, never higher ones.

```bash
export HACASH_HUB_ADDRESS=1YourDedicatedHubAddress
export HACASH_HUB_SECRET_HEX=your64characterhubprivatekey
export HACASH_HUB_JOURNAL_KEY_HEX=yourIndependent64characterJournalKey
export HACASH_HUB_STATE_KEY_HEX=yourDifferent64characterStateKey
export HACASH_NODE_API_TOKEN=yourFullnodeApiToken
export HACASH_HUB_DEPLOYMENT_PROFILE=mainnet-bounded-pilot
export HACASH_HUB_MAINNET_MAX_PAYMENT_HAC_ZHU=100000000
export HACASH_HUB_MAINNET_MAX_CHANNEL_FUNDING_HAC_ZHU=1000000000
export HACASH_HUB_MAINNET_ALLOWED_USERS=1YourPilotUserAddress
export HACASH_HUB_MAINNET_MAX_AGGREGATE_TVL_HAC_ZHU=10000000000

./target/release/fast-pay-hub \
  --listen 127.0.0.1:8790 \
  --node-url http://127.0.0.1:8080 \
  --hub-fee-mei 0 \
  --state-file /var/lib/hpay-fast-pay-hub/hub-state.json
```

Check both endpoints before connecting a wallet:

```bash
curl http://127.0.0.1:8790/v1/health
curl http://127.0.0.1:8790/v1/readiness/mainnet
```

For `mainnet-bounded-pilot`, `payments_enabled` may be `true` only when the node, durable storage, allowlist, TVL and caps are all green; `trusted_bounded_pilot` must be `true`, `wallet_fee_hac` must be `"0"`, and the wallet must have explicit local consent. For `mainnet-pilot`, `payments_enabled` must remain `false` until the rollback-anchor and unilateral-dispute blockers are backed by real independent services and tests. Readiness expires quickly by design; never cache it as permanent approval.

The current Istanbul full node reports `features.channel_unilateral_exit=false`. This is intentional: legacy Go dispute action numbers collide with Istanbul TEX/AST action kinds. Do not override this result with an operator flag and do not copy the legacy codecs into the mainnet registry.

## External rollback anchor (witness)

The anchor is a counter held by a small separate service — the **witness** — that
the Hub asks before it uses its signing key. It exists because every safety check
inside the Hub reads the Hub's own state file, and none of them survive that file
going backwards. A Hub restored from an old backup will re-sign a bill serial it
has already signed, with different balances, and both signatures are valid to the
contract. The witness catches that only because it is not in the Hub's backup set.

**What ships today: no witness configured.** There is no public witness address
yet, so there is no default to point at. A default hostname that did not answer
would be worse than an empty field — the Hub would refuse to sign for a reason
nobody could explain. With no witness configured the Hub starts, prints that it
has no anchor, and measures `external_rollback_anchor_ready = false`. The
trustless `mainnet-pilot` profile therefore stays blocked, which is the honest
result. `mainnet-bounded-pilot` is unaffected: it never claimed an anchor.

**What changes when a public witness exists.** It becomes a documented,
copy-and-paste address in this guide and in `docs/l2/RUNNING-A-WITNESS.md`, and
nothing else. It will never be a compiled-in constant, never a fallback the Hub
reaches for on its own, and never a requirement — a Hub pointed at any other
witness gets identical behaviour and an identical readiness measurement. See
`docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md`, "Who runs the witness".

All five settings are required together. A partial configuration is a startup
failure, never a Hub that quietly runs without an anchor:

```bash
export HACASH_HUB_ROLLBACK_WITNESS_URL=https://witness.example.org
export HACASH_HUB_ROLLBACK_WITNESS_ID=their-witness-id
export HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS=1TheirOnlineReceiptAddress
export HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS=1TheirOfflineAuthorisationAddress
export HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE=/etc/hpay-fast-pay-hub/witness-attestation.json

scripts/START-HUB-WITH-REMOTE-WITNESS.sh https://witness.example.org
```

The witness operator supplies all five values. Moving to a different witness —
your own on separate infrastructure, the counterparty's, a neutral third party's
— is a change to those five values and nothing else. It is not a code change.

**When the witness is unreachable the Hub refuses to sign and channels freeze.**
That is designed, not a defect, and there is no flag, timeout, grace period or
override that changes it: an unreachable oracle is not evidence. If a deployment
cannot accept that availability cost, the honest answer is
`mainnet-bounded-pilot`, which reports `trustless_finality: false` and says out
loud that it depends on trusting the Hub. Do not run a mainnet profile with a
hole in it and call it an anchor.

**It refuses to sign; it does not refuse to run.** A Hub whose witness is
unreachable at startup still starts. It serves reads, `/v1/readiness/mainnet`
and cooperative close, refuses every signature, prints
`rollback_anchor_witness_unreachable`, and publishes that same identifier in the
readiness document's `blockers`. It re-probes every 30 seconds and resumes
signing by itself once the witness answers and agrees, so there is nothing to
restart. This is not a softening of the paragraph above: nothing signs until a
probe agrees. It exists because a Hub that crash-loops under
`Restart=on-failure` cannot serve a close and cannot tell you what is wrong.

**Where the witness sits is published, not hidden.** `/v1/readiness/mainnet`
carries a `rollback_anchor` object beside the flag, naming the attested posture
and operator (`witness_posture`, `witness_operator`) and the Hub's own
measurement of where the witness actually is (`witness_endpoint_is_local`,
`witness_store_in_hub_state_tree`, and the verdict `witness_co_located`). A
wallet, or anyone choosing a Hub, can read whether that Hub witnesses itself
rather than inferring it from a missing blocker string. `null` means no verified
live witness right now; it never means the anchor is optional.

**A mainnet profile refuses to start if a witness store is in its own backup
set.** At startup the Hub looks for a witness append-only log in its state
directory, and directly beside it in the parent, recognising it by its header
rather than its filename. Finding one on `mainnet-pilot` or
`mainnet-bounded-pilot` is a hard refusal naming the exact file, because a
counter that gets restored with the state it guards is not an anchor. Off the
mainnet profiles it is allowed — local development and the Local Pilot need it —
and published as `witness_co_located: true`. This check sees the store beside
your state tree; it cannot see one a directory further out, so it is a lint that
makes the weak layout loud, not a boundary.

| Task | Document |
|---|---|
| Run a witness | `docs/l2/RUNNING-A-WITNESS.md` |
| A Hub has refused to sign | `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md` |
| Why it is built this way | `docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md` |
| Wire protocol | `docs/l2/ROLLBACK-ANCHOR-PROTOCOL.md` |

For local development only, `scripts/DEV-ONLY-HUB-AND-WITNESS-SAME-HOST.sh` (and
the `.bat`) starts a Hub and witness together on one machine. It exercises the
real protocol and anchors nothing, because the witness shares the Hub's
filesystem and backup set. It says so, at length, every time it starts.

## Production hardening

- Keep `--listen` on a private interface and publish only HTTPS port 443 through a reverse proxy with per-IP rate, connection and request-size limits.
- By default the Hub ignores `X-Real-IP` and uses the socket peer. If the Hub itself must rate-limit original clients, set `--trusted-proxy-ip` to the one exact proxy IP and configure that proxy to overwrite, never append, a single `X-Real-IP` value. Never trust a subnet or a public peer.
- Allow the Hub process to reach only its configured local full node.
- Back up the state file, authenticated journal and checkpoint together while the service is stopped.
- Monitor disk space, full-node synchronization, readiness blockers and clock synchronization.
- Stop accepting payments if the journal or state cannot be durably written.
- Start with small liquidity and caps. Raise them only after recovery drills and an independent security audit.
- Run the Hub and miner/full node as separate processes and service accounts. Enabling the Hub must not change mining behavior.

The maintained systemd policy is `scripts/hpay-fast-pay-hub/hpay-fast-pay-hub.service`. Do not keep a second hand-written unit: every hardening or path change must be made once in that canonical file and included unchanged in the release archive.

## Backup and recovery

Treat `/etc/hpay-fast-pay-hub` and `/var/lib/hpay-fast-pay-hub` as one inseparable backup set. The first contains signing and journal keys; the second contains state, the authenticated journal and its checkpoint.

1. Stop the Hub and remove it from the reverse proxy before taking or restoring a backup.
2. Copy both directories to encrypted offline storage while preserving owner and mode. Never upload the backup to GitHub or ordinary cloud storage.
3. Restore only a matching pair onto a clean host while the service is stopped. Never combine state from one snapshot with keys, journal or checkpoint from another.
4. Restore ownership (`root:hpayhub` for the environment file, `hpayhub:hpayhub` for state) and the restrictive permissions installed by the package.
5. Start on loopback, inspect logs, then require green `/v1/health` and `/v1/readiness/mainnet` before restoring traffic.
6. Keep the previous backup until a restart and recovery drill completes successfully.

Never delete, regenerate or manually edit the journal/checkpoint to make the Hub start. A failed authenticated recovery is a safety stop that requires operator investigation.

## Wallet Hub API v7

- `GET /v1/health`: discovery and operational status.
- `GET /v1/readiness/mainnet`: authoritative, short-lived mainnet-pilot gate.
- `POST /v1/fast-pay`: creates a ChannelPay bill for `{ payer, payee, amount, channel_id }`.
- `GET /v1/fast-pay/{id}`: payment status.
- `GET /v1/fast-pay/inbox/{payee}`: routed payments awaiting recipient verification.
- `POST /v1/fast-pay/{id}/confirm`: merges verified signatures and commits only when complete.

## Read-only mainnet infrastructure preflight

Before any canary funding, run the repository preflight against the exact public
HTTPS node and Hub endpoints. It performs no unlock, signing, submission or
state mutation. It reuses the wallet's production validators for node identity,
block 1, freshness, bounded-pilot readiness, zero wallet fee, channel funding,
cooperative close and verified HPAY HVM deployment.

```text
cargo run -p hacash-wallet-core --example hpay_mainnet_infrastructure_preflight -- --node-url https://NODE --hub-url https://HUB --hub-address HUB_HACASH_ADDRESS --payment 0.001 --channel-funding 1
```

A successful result deliberately prints `release_ready: false`. Infrastructure
readiness is necessary but not sufficient: the next gate is the reviewed
small-value mainnet lifecycle `open -> Personal Fast Pay -> Agent Fast Pay ->
cooperative close`, including restart and exact-recovery checks. Preserve the
JSON result with the canary report; never replace a failed field manually.
Follow the exact stop conditions and evidence requirements in
`docs/l2/MAINNET_CANARY_RUNBOOK.md`.

## Cross-channel settlement

Routed payments require two open channels: payer-to-Hub and recipient-to-Hub. The Hub must have enough HAC liquidity on the recipient channel.

1. The Hub prepares the exact ChannelPay documents for both channel legs.
2. The payer verifies the complete intent and signs its leg.
3. The payment becomes `awaiting_recipient` and appears in the recipient inbox.
4. The recipient verifies both legs and signs.
5. The Hub verifies every signature and atomically commits both channel ledgers.

## Testnet/development

For local development, omit `HACASH_HUB_DEPLOYMENT_PROFILE` or set it to `testnet`. Mainnet Wallet clients will not accept this profile. Existing testnet payment behavior remains available, but L1 open/close recovery requires Wallet Hub API v7.

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| Address mismatch | The Hub secret must derive exactly `HACASH_HUB_ADDRESS`. |
| `payments_enabled=false` | Read every entry in `blockers`; verify the full node, clock, profile, caps and durable storage. |
| Full node capability unavailable | Use the HPAY-compatible full node and enable its local capability endpoint. Public legacy nodes cannot authorize mainnet Fast Pay. |
| Channel not found | Check the full-node URL, channel ID and both channel participants. |
| Missing Hub signature | Verify signer configuration and fresh readiness; the Hub intentionally refuses to sign when readiness turns red. |
| Low balance | Add only bounded Hub liquidity or reduce the requested payment. |
| Recovery required | Stop the service and follow **Backup and recovery** above. Preserve the complete matching config/state set; never delete or reconstruct the journal. |

Implementation references: `crates/l2-fast-pay-hub` and `crates/wallet-core/src/l2_hub.rs`.
