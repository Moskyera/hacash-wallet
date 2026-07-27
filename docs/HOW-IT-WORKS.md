# How this wallet works

Written for everyone, not just developers. It explains what protects your money,
what does not, and exactly where the limits are. Where something is a weakness,
it says so.

If you only read one section, read [What this is not](#what-this-is-not).

---

## 1. What this is

A self-custody Hacash wallet for Windows desktop and Android. Self-custody means
there is no company holding your coins and no account to recover. There is a
private key, and whoever has it can spend the money.

Everything else in this wallet exists to do one thing: make it hard for anyone
who is not you to use that key, and make it impossible for the app to sign
something different from what you approved.

## 2. What this is not

**This is not a hardware wallet, and it is not equivalent to one.**

To use your key, the wallet has to decrypt it into the memory of your computer or
phone. While the wallet is unlocked, the key exists in plain form in RAM. Software
running on your device with enough privilege can, in principle, read it.

A hardware wallet is different in kind: the key is generated inside a dedicated
chip, never leaves it, and cannot be exported even by the manufacturer. That is
the property standards like [NIST SP 800-63B AAL3](https://pages.nist.gov/800-63-4/sp800-63b.html)
describe when they require a hardware-based authenticator with a non-exportable
key. **This wallet does not have that property and we do not claim it.**

Why not just put the key in the phone's secure chip? Because it cannot hold this
kind of key. Apple's Secure Enclave and Android's StrongBox support the NIST
P-256 curve. Hacash classic addresses use secp256k1, and Hacash quantum
signatures use ML-DSA. Neither fits in those chips today. This is a hard
technical limit, not an oversight.

So: use this wallet for amounts you are willing to keep on a general-purpose
device. For large holdings, a dedicated hardware signer is a different and
stronger category of protection.

## 3. Where your money actually lives

Your coins are on the Hacash blockchain, not in this app. The blockchain only
checks one thing: is this transaction signed by the key that owns the coins.

That has two consequences people often miss:

- **The app's security settings are not on the blockchain.** They live in a file
  on your device. Anyone holding a copy of your key can sign transactions without
  this app and without any of its restrictions.
- **A backup is a copy of your key.** Treat every backup with exactly the same
  care as the key itself.

## 4. How your key is stored

The key sits in a file called `vault.json`, encrypted so that it is useless
without your passphrase.

- Your passphrase is turned into an encryption key using **Argon2id**, a function
  deliberately designed to be slow and memory-hungry. This is what makes guessing
  passphrases expensive. The "balanced" profile uses 32 MB of memory per attempt;
  the "paranoid" profile uses 128 MB and four passes.
- The key itself is encrypted with **AES-256-GCM**.
- The file also stores non-secret facts: your address, which security policy you
  chose, and which security key you registered. These are not encrypted, but they
  are **cryptographically bound** to the encrypted key. If anyone edits them, the
  file stops decrypting entirely. You cannot weaken your own security policy by
  editing a file.

Wrong-passphrase attempts are slowed down with an increasing delay, so someone
who steals your device cannot try guesses quickly.

## 5. How unlocking works

You type your passphrase, and the key is decrypted into memory for a limited
session. Two independent timers end it:

- An **idle timer**, reset by real activity.
- An **absolute deadline** that nothing can extend. Even continuous use will not
  keep a session open forever.

Locking wipes the key from memory, along with every pending approval.

On Android you can optionally use a fingerprint or face to unlock instead of
typing. Your passphrase is then stored in the phone's hardware-backed keystore,
encrypted with a key the phone will only use after you authenticate. Please read
the next four points before you turn this on, because they describe exactly how
much protection you are getting.

- **Your phone screen lock also opens the wallet.** The unlock prompt accepts
  your fingerprint, your face, *and* your phone PIN, pattern or password.
  Android offers the PIN as a fallback whenever the fingerprint fails, and the
  wallet cannot remove that fallback without breaking fingerprint unlock on many
  phones. So anyone who knows your phone PIN can open the wallet. If that is not
  acceptable to you, leave this feature off and keep typing your passphrase.
- **One authentication covers 30 seconds.** After a successful check, the phone
  will release the stored passphrase for up to 30 seconds without asking again.
  It is not one authentication per single use.
- **Adding a new fingerprint destroys the stored passphrase.** If someone
  enrols their own finger on your phone, Android permanently invalidates the
  key. The wallet cannot unlock with it any more and you have to type your
  passphrase. That is deliberate: it means a new fingerprint cannot be used to
  reach your funds.
- **Turning on Cold Vault deletes the stored passphrase** and disables this
  feature, because a Cold Vault must never be openable by the phone screen lock.

This is a convenience feature. Your passphrase is still the real protection, it
is the only thing that cannot be reset by whoever holds the phone, and unlocking
by any route still puts the key in RAM for the session.

## 6. How sending works, and why it matters

This is the most important protection in the wallet, and it is worth
understanding.

A naive wallet does this: the screen shows you a payment, you click approve, and
the screen then tells the signing code what to sign. The flaw is that the screen
could show you one thing and ask for a different thing to be signed. Malicious
code in the user interface could drain you while displaying a normal payment.

This wallet does not work that way. Sending happens in two separate steps:

1. **Prepare.** The secure core builds the exact transaction itself, computes a
   fingerprint (a SHA-256 digest) that covers the recipient, the amount, the fee,
   the network and the transaction type, and shows you a summary tied to that
   fingerprint.
2. **Execute.** You approve, and then the interface can only say *"run operation
   number 7f3a…"*. **It never gets to supply transaction data.** The bytes stay in
   the secure core the whole time.

On top of that:

- Your biometric or security-key approval is bound to that specific fingerprint,
  not to "a payment" in general.
- Each approval is **single use**. It is consumed when used.
- It **expires after two minutes**.
- Preparing anything new **cancels** the previous approval.
- If the wallet, network or node changed between preparing and executing, it is
  refused.

The practical result: a compromised interface cannot make you sign something you
did not see. It can annoy you, it cannot redirect your money.

## 7. Your choice of security policy

- **Software (default).** The key is protected by your passphrase. A device
  factor is required for every payment **above 99 HAC**. At or below that, while
  the wallet is unlocked, the payment is signed with no further confirmation.
  Please read that twice, because it is the rule that decides your daily
  experience. You can lower that limit on either platform: Settings, Security,
  **Confirmation amount** accepts any whole number of HAC down to 1, and needs
  your passphrase. It can only make the wallet stricter, never looser, because
  your security profile sets the maximum and the wallet always takes the smaller
  of the two. That is also why nobody can weaken it by editing the settings file.
  The limit applies per payment rather than per day, so several payments just
  under it still ask for nothing.

  One consequence to know before you lower it: **Fast Pay cannot be confirmed.**
  Its settlement bill is cosigned by the payment hub, so the wallet cannot bind
  your approval to the exact bill and refuses instead. Any payment that needs
  confirmation has to go on-chain, using Force on-chain (L1), and pay the network
  fee. If you set the limit to 1 HAC, that applies to every payment, and Fast Pay
  effectively stops being available. The Pay screen tells you this before you tap,
  not after.
- **Security-key gate (WebAuthn).** Every payment requires a security key or
  Windows Hello. Fast Pay is refused outright in this mode: its settlement bill
  is cosigned by the payment hub, so the wallet cannot bind your approval to the
  exact bill, and refusing is the honest answer. Use Force L1 instead. Important:
  this is a *gate in front of a software key*, not hardware custody. It stops
  someone who only has your passphrase; it does not move the key into hardware.
- **Cold Vault (air-gap only).** See below.
- **Watch-only.** An address with no key. It can show balances and nothing else.

There is also a stricter **Paranoid** profile that asks for a factor on
effectively every payment, but it demands a security key, which a phone cannot
provide. Android refuses it for that reason rather than letting you lock yourself
out of sending. If you want every payment on a phone confirmed, set the
confirmation amount to 1 HAC instead: every amount rounds up to at least that, so
every payment then asks for your fingerprint, at the cost of Fast Pay described
above. Do not set that on a phone with no working fingerprint or face, because
then nothing can confirm a payment and every send is refused until you raise the
limit again, which needs your passphrase.

Replacing a registered security key requires approval from the key you are
replacing. Otherwise someone with just your passphrase could swap your second
factor for their own, and the gate would protect nobody.

If you lose your only security key, you can still unlock with your passphrase and
switch back to software mode. That is a deliberate, visible downgrade rather than
a silent bypass.

## 8. Cold Vault, in detail

Cold Vault turns a wallet into an offline signer. After activation, this vault
will only ever sign one thing: an exact offline transaction that you reviewed and
freshly approved. Online sending, Fast Pay, dApps and message signing are
permanently blocked. The session is destroyed after every signing attempt.

**Activation is deliberately hard to trigger.** It requires your passphrase *and*
a fresh biometric or security-key ceremony bound to that exact activation. A
correct passphrase alone is not enough, because activation cannot be undone.

**What "cannot be undone" really means.** It is enforced in five independent
places in the code, and editing files does not defeat it. But be precise about
the scope:

> Cold Vault is a property of **this vault file**, not of your key.

Anyone with a **backup taken before activation** can restore an ordinary online
wallet for the same address. Anyone with the raw private key can import it
anywhere. The activation screen states this directly, in the approval prompt
itself: *"Older backups: Still sign online for this address."*

So if you intend Cold Vault as a real boundary, **destroy every backup taken
before you activated it.** That step, not the app, is what makes it real.

To get funds out of a Cold Vault, use it as designed: sign one offline
transaction that moves everything to a newly created wallet.

**A data-loss warning.** If you have a quantum keystore and you change your
wallet passphrase *after* activating Cold Vault, the quantum keystore becomes
permanently unrecoverable. Activation itself preserves it correctly. But a later
passphrase change deliberately never touches the quantum file, while the vault
gets a new random salt. The file's encryption key is derived from your passphrase
together with that salt, so once the old salt is gone, nothing can open the file
again. Export what you need before activating, and do not change your
passphrase afterwards.

## 9. Quantum (Type-4) keys, testnet only

**This is a laboratory feature and it does not work on mainnet.** Quantum Type-4
transactions are refused outside testnet, by the core, before anything is built
or signed. Do not plan to hold or move real funds with a quantum key today. If
you see quantum features in the interface, that is what they are: a testnet
preview of post-quantum signing, not a mainnet custody option.

Hacash supports post-quantum signatures. Those keys live in a separate keystore
with its own password, so a quantum key is never protected only by your wallet
passphrase.

Checking a keystore password is a sensitive operation: answering "does this
password open this file" is exactly what an attacker with a stolen keystore
needs. So the wallet only answers while it is unlocked, refuses entirely once the
vault is a Cold Vault, and applies the same increasing delay as unlocking. It
cannot be used as a fast password-guessing oracle.

## 10. Backups and restoring

The full backup is a single encrypted file containing your vault, your settings,
your quantum keystore if you have one, your payment-channel dispute records and
your encrypted messages. It is encrypted with Argon2id and AES-256-GCM, and
authenticated: if a single byte is altered, restoring fails rather than producing
something subtly wrong.

Restoring is written to be safe against interruption. Every file it replaces is
journalled first, so a crash mid-restore rolls back, and an interrupted rollback
is completed on the next start.

**What restoring an old backup undoes.** A backup captures the security policy at
the moment it was taken. Restoring an older one restores the older policy:

| Change made after the backup | Survives restoring? |
| --- | --- |
| Cold Vault activation | No |
| Replacing your security key | No, the old key works again |
| Security-key usage counter | No, it rolls back |
| Passphrase change | No, the backup's passphrase applies |
| Guessable-key marker | Yes |

The wallet refuses to restore over a live wallet, so an in-app rollback requires
deleting the current one first, which needs your passphrase and your exact
address typed out. That is a speed bump for a local attacker and no defence at
all against someone who simply takes your backup to another machine.

Full detail: [BACKUP-ROLLBACK-POLICY.md](BACKUP-ROLLBACK-POLICY.md).

## 11. Legacy "brainwallet" phrases

Older Hacash tools let you turn a memorable phrase into a key by hashing it once
with SHA-256. **No salt, no slow function, nothing.** Attackers precompute
enormous tables of such phrases and sweep any address that appears. Wallets built
this way have been drained en masse on other chains.

**This wallet cannot make one, at all.** There is no input, and no confirmation
you can type, that turns text into a key. Import accepts exactly one thing: a
64-character hex private key, together with the address it belongs to. Anything
else is refused with a plain error and no alternative offered, because there is
no alternative.

Wallets created before that path was removed are still recognised. The fact is
recorded inside the encrypted file itself, so it survives passphrase changes,
security-profile changes, migrations and backups, cannot be stripped, and cannot
be forged onto a healthy wallet. Such a wallet shows a permanent warning, before
you even unlock it.

Such a wallet is also barred from activating Cold Vault. That is not us being
awkward: Cold Vault promises that only a fresh approved offline signature can move
funds, and that promise is false when anyone who guesses the phrase can sign
without the app. Offering it would be a lie.

### If you have funds in a legacy brainwallet

This wallet cannot recover them for you, and there is one specific mistake to
avoid while you work out how.

**Do not type or paste your phrase into a website.** Not a SHA-256 calculator,
not a key converter, not a recovery helper. A page that computes your key can
also keep it, and you have no way to tell which pages do. Sites exist for no
purpose other than collecting exactly that input. Treating your phrase as
something you can paste into a search box is how these balances usually
disappear, not the weak hashing itself.

What to do instead:

1. Derive the key on a machine with no network connection, using a tool you can
   inspect or already trust. The derivation is a single SHA-256 of the exact
   phrase text, byte for byte, which is what the upstream Hacash tooling does.
2. Import the resulting 64-character key here, together with the address, as any
   other key.
3. Send the entire balance to a newly created wallet, straight away.
4. Never reuse the phrase or the address for anything.

Step 3 is not optional housekeeping. Until it is done, the funds are protected
only by the secrecy of a phrase that is, by construction, guessable.

## 12. Air-gapped signing

You can keep the key on a device that never touches a network:

- An online **watch-only** wallet builds an unsigned transaction and shows it as a
  QR code.
- The **offline** wallet scans it, shows you every field, and signs it after a
  fresh approval.
- The signed result goes back as a QR code, and the online wallet broadcasts it.

The offline device never sees the network and the online device never sees the
key.

## 13. What an attacker has to do

- **Stolen backup or vault file, no passphrase.** They must break Argon2id plus
  AES-256-GCM. With a strong, unique passphrase this is not practical. With a
  weak one, it is only a matter of cost, so choose a long passphrase.
- **Stolen passphrase, no file.** Useless on its own.
- **Both.** They have your money. This is why backups matter as much as keys.
- **Malicious code in the wallet's interface.** It cannot redirect a payment,
  because the interface never supplies transaction data and approvals are bound
  to an exact fingerprint. It also cannot activate Cold Vault, swap your security
  key or read a quantum keystore without a genuine fresh ceremony.
- **Malware with full control of your unlocked device.** It wins. No software
  wallet on a general-purpose device survives this. Only a hardware signer
  changes the answer.

## 14. Current status, honestly

As of this document:

- The security core is covered by an extensive automated test suite, including
  adversarial tests that specifically try to bypass each protection.
- **There has been no independent third-party security audit.** Ours is the only
  review this code has had.
- The published Windows installer is not yet signed by a hardware-backed signing
  service.
- Mobile has not completed a full on-device test pass.

Treat this as software that is being hardened in the open, not as a finished
custody product. Do not put money on it that you cannot afford to lose.

## 15. Checking this for yourself

Everything above is in the source, and the security claims have tests you can
run. Useful starting points:

| What | Where |
| --- | --- |
| Exact-operation approvals | `crates/wallet-core/src/authorization.rs` |
| Vault encryption and metadata binding | `crates/wallet-core/src/vault.rs` |
| Cold Vault rules | `crates/wallet-core/tests/cold_vault_policy.rs` |
| Security-key replacement | `crates/wallet-core/tests/webauthn_replacement_gate.rs` |
| Brainwallet quarantine | `crates/wallet-core/tests/legacy_brainwallet_quarantine.rs` |
| Keystore-password throttling | `crates/wallet-core/tests/quantum_keystore_oracle.rs` |
| Backup and restore | `crates/wallet-tauri-common/src/backup_commands/bundle.rs` |

Run them with:

```bash
cargo test -p hacash-wallet-core -p wallet-tauri-common
```

If you find something wrong in this document, that is a bug worth reporting. A
security document that overstates protection is worse than no document.
