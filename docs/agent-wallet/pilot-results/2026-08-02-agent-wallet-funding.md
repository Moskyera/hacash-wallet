# HPAY Agent Wallet Local Pilot funding evidence

Date: 2026-08-02

## Scope and stop point

This record covers only ownership verification, exact Local Pilot network
binding, miner reward configuration and Agent Wallet funding. It stops before
payment preparation, approval, signing or broadcast.

No private key, seed, mnemonic, passphrase, vault plaintext, recovery secret,
signing secret, journal key, pairing token, raw transaction or signature was
requested, read, displayed or recorded.

## Wallet ownership

| Field | Value |
|---|---|
| Public Agent address | `1QGpzAdoDJoCYewETU6mNZmaFfd1By4wD2` |
| User-confirmed state | Agent Wallet opened after unlock |
| Unlock integrity contract | Authenticated vault payload verified |
| Address ownership contract | Address derived from the decrypted Agent secret must equal both vault metadata and the secret-free public registry entry |
| Secret exposure | None |

The desktop unlock path fails closed if the registry, encrypted vault metadata,
authenticated wallet state or address derived from the Agent signing secret do
not agree. Reaching the unlocked Agent Wallet therefore verifies ownership
without exposing the secret.

## Exact network binding

| Field | Value |
|---|---|
| Evidence category | `LOCAL_PRIVATE_CHAIN` |
| Node | `hacash-fullnode 1.0.10` |
| Endpoint | `http://127.0.0.1:8197` |
| Network kind | `local_pilot_v1` |
| Node profile | `hpay-local-pilot-chain-v1` |
| Chain ID | `7` |
| Mainnet | `false` |
| Block 1 | `000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29` |
| Network instance | `9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3` |
| Transaction format | `2` |

The active process was the dedicated Local Pilot binary and configuration. The
node was restarted against the existing data directory after the public funding
address was configured. Block 1 and the network instance remained unchanged,
proving that no new chain or fallback network was introduced.

## Funding result

| Field | Before | After |
|---|---:|---:|
| Height | `12` | `20` |
| Public Agent HAC balance | `0` | `8` |
| `funding_confirmed` | `false` | `true` |
| `transaction_ready` | `false` | `true` |

The active Local Pilot configuration changed only the two public fields needed
for deterministic funding verification:

- miner reward address: the public Agent address;
- pilot funding target: the same public Agent address.

The CPU miner was stopped immediately after the first observed height increase.
Because this isolated chain has intentionally low pilot difficulty, eight blocks
were accepted before process termination completed. Heights 13 through 20 each
name the Agent address as miner and each reports zero normal transactions. The
resulting 8 HAC has no mainnet value and exists only on this private chain.

Post-stop verification at `2026-08-02T15:06:46Z` showed:

- miner process not running;
- height stable at 20 across repeated queries;
- public balance 8 HAC;
- `funding_confirmed = true`;
- `transaction_ready = true`.

## Payment safety boundary

| Stage | Result |
|---|---|
| Payment request created | No |
| Approval created | No |
| Transaction prepared | No |
| Agent transaction signed | No |
| Transaction broadcast | No |
| Normal transactions in funding blocks | `0` |
| Wallet fee | `0` for Agent Wallet |

## Verification gates

| Gate | Result |
|---|---|
| Local Pilot launcher validation with exact public funding/reward address | Passed; validation-only, no process or files created |
| Agent Core Pilot | 137 passed |
| Agent Core non-Pilot | 110 passed |
| Desktop Tauri IPC/security Pilot | 67 passed |
| Desktop Tauri IPC/security non-Pilot | 51 passed |
| Agent Core Pilot strict Clippy (`-D warnings`) | Passed |
| Workspace-wide Rust format check | Not clean because of pre-existing formatting diffs in the separate fullnode/miner workspace; no formatting rewrite was performed |

Final classification: `Local Pilot Agent funding verified; payment pilot not started`.
