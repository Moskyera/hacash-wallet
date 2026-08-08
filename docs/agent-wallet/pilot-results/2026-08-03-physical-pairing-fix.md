# Physical companion pairing: early eof root cause

Date: 2026-08-03
Branch: codex/how-it-works-hacd-fidelity
HEAD: 26ae4c5d0367aa7a59aab17abd8a8a8a15293e90
Worktree: dirty (207 modified, 171 untracked, 5513 deletions, all under releases/)

No commit, staging, push, tag or release was made. No payment, signing,
broadcast or mining occurred. The miner was not started.

## Evidence classification

| Class | Covered here |
| --- | --- |
| SOURCE_VERIFIED | protocol version, framing, admission control, startup gate, silent-close paths |
| AUTOMATED | companion protocol and LAN runtime test suites, prove-the-test mutation |
| PHYSICAL_ANDROID | live DOM measurement and installed-build identity on the paired phone |
| SAME_LAN_PAIRING | live TCP probes of the desktop companion listener over the LAN |
| WITNESS_BASELINE | NOT_EXECUTED |
| RESTART_RECONNECT | NOT_EXECUTED |

## 1. Protocol version, confirmed not assumed

`crates/companion-protocol/src/message.rs:16` declares `PROTOCOL_VERSION: u64 = 3`,
enforced by strict equality at `message.rs:183` and `message.rs:216`. There is no
forward compatibility and no negotiation. Protocol version was left at 3.

## 2. The error string is not in the source

`early eof` appears nowhere in the tree. `crates/companion-lan-runtime/src/error.rs:21`
formats `companion LAN I/O failed: {0}` from a `std::io::Error`. The phone's message
is therefore the Display of an `UnexpectedEof` raised by `read_exact` in
`crates/companion-lan-runtime/src/framing.rs:62`, reading the four byte length
prefix of the reply that never arrived.

Framing is a single shared implementation used by both sides, so a desktop and
mobile framing mismatch is excluded by construction.

## 3. Live probe: the accept path is healthy

Desktop listener observed LISTENING on `192.168.129.14:42492`, owned by
`hacash-wallet.exe`. No established companion connection was present.

Probe A, connect and send nothing:

```text
connected in 0.019s
server closed with no data after 10.029s
```

10.029s is `handshake_timeout` (`config.rs:75`). The desktop accepted the socket
and waited for a ClientHello. That single measurement clears, at runtime and not
on inspection, every silent-drop path ahead of the first read:

- `validate_peer_ip` accepted the LAN source address
- the global connection semaphore had capacity
- `AdmissionControl::admit` granted a peer permit
- `RuntimeStartupGate::validate()` passed, so `agent_space_active`,
  `connectivity_enabled` and `active_paired_devices > 0` all held

Probe B, send a well formed ClientHello carrying a device id the desktop does not
know:

```text
unknown device id      -> silent close after 0.003s, zero bytes written
short/invalid device id -> silent close after 0.013s, zero bytes written
```

## 4. Root cause

`handle_connection` in `crates/companion-lan-runtime/src/server.rs:168` performs
device admission before it writes anything. When `decode_client_hello` or
`backend.begin(...)` rejects, the function returns `Err`, the `TcpStream` is
dropped, and the desktop closes having written zero bytes.

The phone is at that moment inside `read_packet` waiting for the SessionChallenge
prefix. It receives end of stream and can only report `UnexpectedEof`.

**A device refusal by the desktop and a broken network are the same event on the
wire.** The owner is shown the network reading of a refusal.

Why this phone is refused is visible in its own UI: the companion renders the
`pendingPairingFinalization` panel, "ONE LAST STEP, finish the phone connection".
The pairing was started and stored on the phone but never finalized on the
desktop, so the desktop holds no active record for it. Every reconnect is
therefore refused, silently, forever, while the phone displays "Paired,
disconnected" and an I/O error.

Close initiator: the desktop. Last successful stage: ClientHello accepted and
decoded. Failing stage: device admission, before the first desktop write.

## 5. Scoped fix

No protocol change, no schema change, no wire message added, no authentication,
encryption, network binding or witness check weakened. Protocol remains 3.

`error.rs` gains three stage errors and a single guard:

```rust
pub(crate) fn at_stage(self, stage: LanRuntimeError) -> Self {
    match &self {
        Self::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => stage,
        _ => self,
    }
}
```

Applied at the three mobile reads in `mobile.rs`: device authentication, session
key confirmation, and the authenticated session loop. Only an end of stream is
relabelled, so a timeout stays a timeout and a refused connection stays an I/O
error. A refusal now reads:

```text
the paired desktop closed the connection during device authentication without
replying, which means it refused this device. Finish pairing on the desktop, or
pair again.
```

## 6. Tests

`cargo test -p hpay-companion-lan-runtime` 22 passed.
`cargo test -p hpay-companion-protocol` 87 passed.
`cargo check --workspace` clean.

Prove the test, per the mutation requirement: with the stage mapping removed, the
new test fails with

```text
expected the authentication stage, got Io(Custom { kind: UnexpectedEof, error: "early eof" })
```

which is character for character the string reported from the physical device.
The implementation was restored immediately and the suite returned to 22 passed.

## 7. Status

The accurate reading of this stage is:

```text
Physical defect reproduced
Pairing root cause identified
Source-level diagnostic fix completed
Corrected physical build not yet verified
Pairing finalization still pending
```

It is not yet "physical UI verified" in general. The measurements were taken on
the build that carries the defect. A build containing the corrections has not
been installed or observed on the device.

## 8. Protocol v3 wording and pending-pairing behaviour

Applied in the same checkpoint, ahead of a single shared build:

- The per request cap is labelled "Maximum total debit per request" and states
  that it includes the Hacash network fee, matching `total_debit` in
  `validate_policy_for_request`.
- The daily cap is labelled "Rolling 24-hour spending limit" and states that
  pending and reserved requests may count, matching
  `exposure_for_agent_in_window(..., 86_400)`.
- The remaining-allowance bar is removed. It drew wallet-wide committed spend
  against one agent's cap, which is a different quantity and scope from the
  enforced figure. Protocol v3 does not carry the inputs, so the interface now
  says so instead of drawing a number it cannot compute.
- "Spent today" and "Spent this month" are renamed "Completed, last 24 hours"
  and "Completed, last 31 days", with a note that they are not the enforcement
  value. Those are the actual windows, `86_400` and `31 * 86_400`, over
  committed operations only.
- Emergency stop wording on both platforms now states that it blocks new agent
  payment progress and invalidates active permits, and that it cannot reverse a
  transaction already submitted to the network. Mobile states that emergency
  stop is available from HPAY Desktop. No mobile emergency command was built.
- While `pendingPairingFinalization` holds, the phone no longer attempts the
  connection the desktop is certain to refuse. It explains that the desktop has
  not completed pairing, shows identity, approval, transport and witness as
  separate states, and offers a retry that only re-reads stored state and
  connects once the desktop has approved. It never mints an identity, starts a
  second pairing, clears pending state or touches a witness epoch.
- The desktop empty device list explains that a phone showing "One last step" is
  not yet authorized here and will be refused until pairing is finished.

Protocol version is unchanged at 3. No wire message was added.

## 9. Not executed

Fresh Windows Pilot build, fresh Android ARM64 APK, safe device update,
post-fix physical UI verification, authenticated pairing, initial witness
baseline, and all reconnect verification remain outstanding. The mobile UI
changes exist in source and are covered by automated tests, but have not been
observed on the device in a build containing them.
