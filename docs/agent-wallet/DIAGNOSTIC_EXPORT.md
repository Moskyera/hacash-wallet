# HPAY Agent Wallet Pilot Diagnostic Export

Status: implemented for the strict testnet pilot. Export is local-only and is
available only to the trusted desktop wallet webview.

## Allowlisted schema

Schema version 1 may contain only:

- application, pilot protocol, platform, and build profile;
- testnet network id, verified node profile id, and a bounded capability
  summary;
- domain-separated redacted wallet, agent, desktop, and mobile identifiers;
- witness, signer, journal, anchor, and rotation epochs/phases;
- typed operation state names and typed error codes;
- public transaction ids;
- explicit build/artifact hashes and test summaries when supplied;
- the authenticated state update time.

Identifiers are SHA-256 derived under
`HPAY/AGENT/DIAGNOSTIC-REDACTION/V1` with a domain tag and are truncated for
display. Redaction is deterministic within each domain and different across
domains.

The schema explicitly excludes private keys and seeds, passphrases, vault
plaintext, journal/vault keys, device/session private keys, pairing secrets,
tokens, raw transactions, signatures, AI prompts, environment data, and
filesystem paths.

## Export ceremony

1. The trusted desktop UI requests a preview from an unlocked Agent Wallet.
2. The user sees included and excluded categories plus the exact preview
   SHA-256.
3. Export requires explicit confirmation of that same hash.
4. The destination must be a new `.json` file. Existing files are never
   overwritten.
5. The payload is bounded to 256 KiB, written with the shared secure atomic
   writer, read back byte-for-byte, and returned with final size and SHA-256.
6. No upload, telemetry, clipboard copy, or automatic support submission
   exists.

## Verification

Automated marker tests place private-key, passphrase, session-secret, and
signed-body marker strings into source identifiers and prove that no marker
appears in the exported bytes. Tests also reject a changed confirmation hash,
an existing destination, a non-JSON destination, and an oversized payload.

No real wallet diagnostic file was exported at this checkpoint because no
physical-device/live-node Pilot session was available. The automated temporary
exports are not presented as real incident evidence.

