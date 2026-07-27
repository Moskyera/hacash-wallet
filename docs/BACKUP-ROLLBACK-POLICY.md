# Backup rollback policy

What restoring an older backup can and cannot undo, stated plainly. This document
exists because several wallet features are described as irreversible, and that
claim is only true within a narrow scope. Anywhere the UI or release notes
describe a one-way security change, this file is the authority on its real limit.

## The one sentence version

A backup is a copy of the private key. Security policy is stored *next to* the
key, not *inside* it, so restoring an older backup restores the older policy.
Nothing the wallet can do changes that, because whoever holds the key can sign
without the wallet at all.

## What a restore is allowed to do

`bundle::restore` refuses to run unless the profile is empty
(`crates/wallet-tauri-common/src/backup_commands/bundle.rs`). Restoring over a
live wallet is therefore a two-step act:

1. `wallet_reset`, which requires the current passphrase **and** the exact wallet
   address typed as confirmation.
2. `wallet_import_backup` into the now-empty profile.

Consequence: an attacker who steals only a backup file and its passphrase cannot
silently roll back a running installation. They can, however, restore that backup
on **their own** machine, and then they simply hold the key. Reset is a speed
bump for the local case; it is not a defence for the stolen-backup case.

## What an older backup does undo

| Change made after the backup | Survives a restore? |
| --- | --- |
| Cold Vault activation | **No.** The restored wallet is an ordinary online software wallet for the same address. |
| WebAuthn authenticator replacement | **No.** The retired authenticator becomes valid again. |
| WebAuthn signature counter | **No.** The counter rolls back, so assertions counted above the restored value are accepted again. |
| Security profile / signing policy | **No.** Whatever the backup recorded wins. |
| Passphrase change | **No.** The backup's own passphrase applies. |
| Legacy brainwallet marker | **Yes**, for any backup taken after the marker existed. It lives inside the authenticated vault metadata and survives every migration and re-encryption. |

A legacy classic-key-only backup carries no policy at all, so it always restores
as a plain online software wallet.

## Why this is not enforced

The wallet could keep a monotonic "policy floor" file recording that this device
once had Cold Vault, and refuse to restore anything weaker. That was considered
and deliberately rejected:

- Any attacker who can place a backup file can also delete that marker, so it
  stops no attack in the threat model where it would matter.
- It would still not constrain a restore on a different device, which is the
  realistic path.
- It would create a false impression that Cold Vault is enforced across backups,
  which is the exact misunderstanding this document is meant to prevent.

So the policy is honesty plus a clear consent step, not a control that cannot
hold. The restore preview states what a rollback undoes before the user commits,
and the Cold Vault activation ceremony itself carries an
`Older backups: Still sign online for this address` field.

## Correct operating procedure

For anyone treating Cold Vault as a custody boundary:

1. Activate Cold Vault on a device that will stay offline.
2. **Destroy every backup taken before activation.** They are equivalent to the
   key with no Cold Vault restriction. This is the only step that makes the
   restriction real.
3. Take a fresh backup afterwards, and treat that backup with the same care as
   the key itself.

For a rotated WebAuthn authenticator: destroy backups taken before the rotation,
otherwise the retired authenticator remains usable via a restore.

For a recovered legacy brainwallet: none of the above helps. The phrase itself
reproduces the key, so the only fix is to move the funds to a newly generated
random key.

## What this does not cover

- Deliberate rollback by the device owner. That is a supported action, gated by
  reset, and documented above.
- Filesystem-level attackers, who are out of scope for a software wallet on a
  general-purpose device. See the custody limits in `README` and the security
  screens: the private key is decrypted into device memory while unlocked, so
  this wallet is not equivalent to a hardware wallet with a non-exportable key.
