use std::collections::BTreeSet;

use super::*;
use crate::error::CompanionError;
use crate::identity::{
    DeviceId, DevicePermission, DeviceRegistry, DeviceRole, DeviceSignaturePurpose,
    SoftwareDeviceIdentity, sign_with_platform,
};
use crate::replay::ReplayGuard;

struct Fixture {
    desktop: SoftwareDeviceIdentity,
    mobile: SoftwareDeviceIdentity,
    registry: DeviceRegistry,
}

impl Fixture {
    fn new(wallet: &str) -> Self {
        let desktop = SoftwareDeviceIdentity::generate(DeviceRole::Desktop);
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut registry = DeviceRegistry::new();
        registry
            .register(desktop.public_record(wallet, BTreeSet::new(), 90).unwrap())
            .unwrap();
        registry
            .register(
                mobile
                    .public_record(
                        wallet,
                        BTreeSet::from([DevicePermission::ViewAgentWalletStatus]),
                        90,
                    )
                    .unwrap(),
            )
            .unwrap();
        Self {
            desktop,
            mobile,
            registry,
        }
    }

    async fn desktop_attempt(&self) -> DesktopSessionAttempt {
        DesktopSessionAttempt::start(
            &self.desktop,
            &self.registry,
            "wallet_one",
            self.mobile.device_id().clone(),
            1,
            100,
            60,
        )
        .await
        .unwrap()
    }

    async fn mobile_attempt(
        &self,
        desktop: &DesktopSessionAttempt,
        replay: &mut ReplayGuard,
    ) -> MobileSessionAttempt {
        MobileSessionAttempt::respond(
            desktop.challenge().clone(),
            &self.mobile,
            &self.registry,
            replay,
            1,
            101,
        )
        .await
        .unwrap()
    }
}

fn corrupt_hex(value: &mut String) {
    let replacement = if value.starts_with("00") { "01" } else { "00" };
    value.replace_range(0..2, replacement);
}

#[tokio::test]
async fn valid_reconnect_derives_same_fresh_memory_only_key() {
    let fixture = Fixture::new("wallet_one");
    let mut desktop = fixture.desktop_attempt().await;
    let next = fixture.desktop_attempt().await;
    assert_ne!(
        desktop.challenge().desktop_ephemeral_public_key,
        next.challenge().desktop_ephemeral_public_key
    );
    let mut mobile_replay = ReplayGuard::new();
    let mobile = fixture.mobile_attempt(&desktop, &mut mobile_replay).await;
    let mut desktop_replay = ReplayGuard::new();
    let (confirmation, desktop_session) = desktop
        .accept_response(
            mobile.response(),
            &fixture.desktop,
            &fixture.registry,
            &mut desktop_replay,
            102,
        )
        .await
        .unwrap();
    let mobile_session = mobile
        .verify_confirmation(&confirmation, &fixture.registry, 103)
        .unwrap();
    assert_eq!(
        desktop_session.session_key_for_testing(),
        mobile_session.session_key_for_testing()
    );
    assert!(format!("{desktop_session:?}").contains("<memory-only>"));
    assert!(
        !format!("{desktop_session:?}")
            .contains(&hex::encode(desktop_session.session_key_for_testing()))
    );
}

#[tokio::test]
async fn unknown_revoked_cross_wallet_and_wrong_role_fail() {
    let fixture = Fixture::new("wallet_one");
    let unknown = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    assert_eq!(
        DesktopSessionAttempt::start(
            &fixture.desktop,
            &fixture.registry,
            "wallet_one",
            unknown.device_id().clone(),
            1,
            100,
            60,
        )
        .await
        .unwrap_err(),
        CompanionError::UnknownDevice
    );
    let mut revoked = fixture.registry.clone();
    revoked.revoke(fixture.mobile.device_id(), 99).unwrap();
    assert_eq!(
        DesktopSessionAttempt::start(
            &fixture.desktop,
            &revoked,
            "wallet_one",
            fixture.mobile.device_id().clone(),
            1,
            100,
            60,
        )
        .await
        .unwrap_err(),
        CompanionError::DeviceRevoked
    );
    assert_eq!(
        DesktopSessionAttempt::start(
            &fixture.desktop,
            &fixture.registry,
            "wallet_other",
            fixture.mobile.device_id().clone(),
            1,
            100,
            60,
        )
        .await
        .unwrap_err(),
        CompanionError::WalletScopeMismatch
    );
    assert_eq!(
        DesktopSessionAttempt::start(
            &fixture.mobile,
            &fixture.registry,
            "wallet_one",
            fixture.desktop.device_id().clone(),
            1,
            100,
            60,
        )
        .await
        .unwrap_err(),
        CompanionError::WalletScopeMismatch
    );
}

#[tokio::test]
async fn wrong_device_fingerprint_and_desktop_signature_fail() {
    let fixture = Fixture::new("wallet_one");
    let desktop = fixture.desktop_attempt().await;
    let mut wrong_device = desktop.challenge().clone();
    wrong_device.mobile_device_id = DeviceId::parse("mobile_unknown").unwrap();
    assert_eq!(
        MobileSessionAttempt::respond(
            wrong_device,
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            101,
        )
        .await
        .unwrap_err(),
        CompanionError::UnknownDevice
    );
    let mut wrong_fingerprint = desktop.challenge().clone();
    wrong_fingerprint.mobile_identity_fingerprint = "11".repeat(32);
    assert_eq!(
        MobileSessionAttempt::respond(
            wrong_fingerprint,
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            101,
        )
        .await
        .unwrap_err(),
        CompanionError::FingerprintMismatch
    );
    let mut wrong_signature = desktop.challenge().clone();
    corrupt_hex(&mut wrong_signature.desktop_identity_signature);
    assert_eq!(
        MobileSessionAttempt::respond(
            wrong_signature,
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            101,
        )
        .await
        .unwrap_err(),
        CompanionError::InvalidSignature
    );
}

#[tokio::test]
async fn stale_epochs_and_revocation_during_handshake_fail() {
    let fixture = Fixture::new("wallet_one");
    let mut stale = fixture.desktop_attempt().await.challenge().clone();
    stale.mobile_authorization_epoch += 1;
    assert_eq!(
        MobileSessionAttempt::respond(
            stale,
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            101,
        )
        .await
        .unwrap_err(),
        CompanionError::AuthorizationEpochMismatch
    );

    let mut desktop = fixture.desktop_attempt().await;
    let mobile = fixture
        .mobile_attempt(&desktop, &mut ReplayGuard::new())
        .await;
    let mut revoked = fixture.registry.clone();
    revoked.revoke(fixture.mobile.device_id(), 102).unwrap();
    assert_eq!(
        desktop
            .accept_response(
                mobile.response(),
                &fixture.desktop,
                &revoked,
                &mut ReplayGuard::new(),
                102,
            )
            .await
            .unwrap_err(),
        CompanionError::DeviceRevoked
    );
}

#[tokio::test]
async fn expiry_tampered_ephemeral_and_noncontributory_key_fail() {
    let fixture = Fixture::new("wallet_one");
    let desktop = fixture.desktop_attempt().await;
    assert_eq!(
        MobileSessionAttempt::respond(
            desktop.challenge().clone(),
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            160,
        )
        .await
        .unwrap_err(),
        CompanionError::Expired
    );
    let mut tampered = desktop.challenge().clone();
    tampered.desktop_ephemeral_public_key = "11".repeat(32);
    assert_eq!(
        MobileSessionAttempt::respond(
            tampered,
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            101,
        )
        .await
        .unwrap_err(),
        CompanionError::InvalidSignature
    );
    let mut zero = desktop.challenge().clone();
    zero.desktop_ephemeral_public_key = "00".repeat(32);
    zero.desktop_identity_signature = sign_with_platform(
        &fixture.desktop,
        DeviceSignaturePurpose::SessionChallenge,
        &zero.unsigned_bytes().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        MobileSessionAttempt::respond(
            zero,
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            101,
        )
        .await
        .unwrap_err(),
        CompanionError::Crypto
    );
}

#[tokio::test]
async fn mobile_signature_tamper_and_response_binding_fail() {
    let fixture = Fixture::new("wallet_one");
    let mut desktop = fixture.desktop_attempt().await;
    let mobile = fixture
        .mobile_attempt(&desktop, &mut ReplayGuard::new())
        .await;
    let mut response = mobile.response().clone();
    corrupt_hex(&mut response.mobile_identity_signature);
    assert_eq!(
        desktop
            .accept_response(
                &response,
                &fixture.desktop,
                &fixture.registry,
                &mut ReplayGuard::new(),
                102,
            )
            .await
            .unwrap_err(),
        CompanionError::InvalidSignature
    );
    let mut rebound = mobile.response().clone();
    rebound.agent_wallet_id = "wallet_other".to_owned();
    assert_eq!(
        desktop
            .accept_response(
                &rebound,
                &fixture.desktop,
                &fixture.registry,
                &mut ReplayGuard::new(),
                102,
            )
            .await
            .unwrap_err(),
        CompanionError::InvalidSession
    );
}

#[tokio::test]
async fn challenge_response_replay_and_attempt_reuse_fail() {
    let fixture = Fixture::new("wallet_one");
    let mut desktop = fixture.desktop_attempt().await;
    let mut mobile_replay = ReplayGuard::new();
    let mobile = fixture.mobile_attempt(&desktop, &mut mobile_replay).await;
    assert_eq!(
        MobileSessionAttempt::respond(
            desktop.challenge().clone(),
            &fixture.mobile,
            &fixture.registry,
            &mut mobile_replay,
            2,
            102,
        )
        .await
        .unwrap_err(),
        CompanionError::SequenceReplay
    );
    let response = mobile.response().clone();
    let mut desktop_replay = ReplayGuard::new();
    let (confirmation, _) = desktop
        .accept_response(
            &response,
            &fixture.desktop,
            &fixture.registry,
            &mut desktop_replay,
            102,
        )
        .await
        .unwrap();
    assert_eq!(
        desktop_replay.check(&response.replay_metadata(), 103),
        Err(CompanionError::SequenceReplay)
    );
    assert_eq!(
        desktop
            .accept_response(
                &response,
                &fixture.desktop,
                &fixture.registry,
                &mut desktop_replay,
                103,
            )
            .await
            .unwrap_err(),
        CompanionError::InvalidSession
    );
    mobile
        .verify_confirmation(&confirmation, &fixture.registry, 103)
        .unwrap();
}

#[tokio::test]
async fn current_epochs_remain_required_after_establishment() {
    let fixture = Fixture::new("wallet_one");
    let mut desktop = fixture.desktop_attempt().await;
    let mobile = fixture
        .mobile_attempt(&desktop, &mut ReplayGuard::new())
        .await;
    let (confirmation, established) = desktop
        .accept_response(
            mobile.response(),
            &fixture.desktop,
            &fixture.registry,
            &mut ReplayGuard::new(),
            102,
        )
        .await
        .unwrap();
    mobile
        .verify_confirmation(&confirmation, &fixture.registry, 103)
        .unwrap();
    established.validate_at(&fixture.registry, 103).unwrap();
    let mut revoked = fixture.registry.clone();
    revoked.revoke(fixture.mobile.device_id(), 104).unwrap();
    assert_eq!(
        established.validate_at(&revoked, 104),
        Err(CompanionError::DeviceRevoked)
    );
    assert_eq!(
        established.validate_at(&fixture.registry, 160),
        Err(CompanionError::InvalidSession)
    );
}

#[tokio::test]
async fn canonical_decode_is_exact_and_old_versions_fail() {
    let fixture = Fixture::new("wallet_one");
    let desktop = fixture.desktop_attempt().await;
    let challenge = desktop.challenge();
    let bytes = challenge.to_bytes().unwrap();
    assert_eq!(SessionChallenge::from_bytes(&bytes).unwrap(), *challenge);
    for end in 0..bytes.len() {
        assert!(SessionChallenge::from_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        SessionChallenge::from_bytes(&trailing),
        Err(CompanionError::MalformedMessage)
    );
    let marker = b"SESSION-CHALLENGE-WIRE/V1";
    let mut old_domain = bytes;
    let offset = old_domain
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    old_domain[offset + marker.len() - 1] = b'0';
    assert_eq!(
        SessionChallenge::from_bytes(&old_domain),
        Err(CompanionError::MalformedMessage)
    );
    let mut old_version = challenge.clone();
    old_version.protocol_version = 0;
    assert_eq!(
        old_version.to_bytes(),
        Err(CompanionError::UnsupportedVersion)
    );
}

/// Reconnect at the exact unix seconds and clock offset measured on the live
/// pair, wired the way production wires it:
///
/// * desktop: `DesktopChallengeSequence` -> `DesktopSessionAttempt::start`
///   with `SESSION_LIFETIME_SECS` (crates/wallet-tauri-common/src/companion_backend.rs)
/// * phone:   `MobileSessionAttempt::respond`
///   (apps/mobile/src-tauri/src/agent_companion/session.rs)
///
/// The first two tests are the whole argument about cause. With one clock the
/// handshake succeeds, which acquits the challenge-sequence source of the live
/// failure. With the measured one second of skew, and nothing else changed, it
/// used to be refused; it must now succeed end to end.
///
/// The rest hold the line the fix must not cross: the budget is bounded, an
/// expired challenge is still refused, and a reoffered sequence is still
/// refused as a replay.
mod live_reconnect_clock_skew {
    use super::*;
    use crate::error::CompanionResult;
    use crate::replay::MAX_CLOCK_SKEW_SECS;
    use crate::session::DesktopChallengeSequence;
    use crate::session::validation::{
        MAX_HANDSHAKE_LIFETIME_SECS, MAX_REQUESTED_SESSION_LIFETIME_SECS,
    };

    /// Desktop `SystemTime::now()`, measured.
    const DESKTOP_NOW: u64 = 1_785_836_273;
    /// Phone `SystemTime::now()`, measured in the same instant. One second behind.
    const PHONE_NOW: u64 = 1_785_836_272;
    /// What the production desktop backend asks for, taken from the protocol
    /// rather than restated here so the two cannot drift apart
    /// (crates/wallet-tauri-common/src/companion_backend.rs).
    const SESSION_LIFETIME_SECS: u64 = MAX_REQUESTED_SESSION_LIFETIME_SECS;

    async fn production_challenge(fixture: &Fixture, now: u64) -> DesktopSessionAttempt {
        let sequence = DesktopChallengeSequence::new().next(0, now).unwrap();
        // ~1.87e15: the value the investigation asks about.
        assert_eq!(sequence, now << 20);
        challenge_with_sequence(fixture, sequence, now).await
    }

    async fn challenge_with_sequence(
        fixture: &Fixture,
        sequence: u64,
        now: u64,
    ) -> DesktopSessionAttempt {
        DesktopSessionAttempt::start(
            &fixture.desktop,
            &fixture.registry,
            "wallet_one",
            fixture.mobile.device_id().clone(),
            sequence,
            now,
            SESSION_LIFETIME_SECS,
        )
        .await
        .unwrap()
    }

    /// Runs the complete three-message handshake with the desktop on one clock
    /// and the phone on another, and returns whatever the phone's last step
    /// returned. Every step is given the clock of the device that performs it,
    /// which is the thing the single-clock tests elsewhere in this file cannot
    /// express.
    async fn handshake_across_two_clocks(
        fixture: &Fixture,
        desktop_now: u64,
        phone_now: u64,
    ) -> CompanionResult<()> {
        let mut desktop = production_challenge(fixture, desktop_now).await;
        let mobile = MobileSessionAttempt::respond(
            desktop.challenge().clone(),
            &fixture.mobile,
            &fixture.registry,
            &mut ReplayGuard::new(),
            1,
            phone_now,
        )
        .await?;
        let (confirmation, desktop_session) = desktop
            .accept_response(
                mobile.response(),
                &fixture.desktop,
                &fixture.registry,
                &mut ReplayGuard::new(),
                desktop_now,
            )
            .await?;
        let mobile_session =
            mobile.verify_confirmation(&confirmation, &fixture.registry, phone_now)?;
        assert_eq!(
            desktop_session.session_key_for_testing(),
            mobile_session.session_key_for_testing(),
            "both devices must derive the same session key across a clock offset",
        );
        Ok(())
    }

    /// Control, and the acquittal of the challenge-sequence source. One clock,
    /// production wiring, handshake accepted. The 1.87e15 sequence reaches
    /// `challenge_sequence` and nothing else: `issued_at` and `expires_at` are
    /// the wall clock and the wall clock plus the requested lifetime, before and
    /// after a wire round trip.
    #[tokio::test]
    async fn one_clock_accepts_the_production_challenge_sequence() {
        let fixture = Fixture::new("wallet_one");
        let desktop = production_challenge(&fixture, DESKTOP_NOW).await;
        let challenge = desktop.challenge();

        assert_eq!(challenge.challenge_sequence, DESKTOP_NOW << 20);
        assert_eq!(challenge.issued_at, DESKTOP_NOW);
        assert_eq!(challenge.expires_at, DESKTOP_NOW + SESSION_LIFETIME_SECS);
        let decoded = SessionChallenge::from_bytes(&challenge.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded, *challenge);
        assert_eq!(decoded.issued_at, DESKTOP_NOW);
        assert_eq!(decoded.expires_at, DESKTOP_NOW + SESSION_LIFETIME_SECS);
        let metadata = challenge.replay_metadata();
        assert_eq!(metadata.sequence, DESKTOP_NOW << 20);
        assert_eq!(metadata.issued_at, DESKTOP_NOW);
        assert_eq!(metadata.expires_at, DESKTOP_NOW + SESSION_LIFETIME_SECS);

        handshake_across_two_clocks(&fixture, DESKTOP_NOW, DESKTOP_NOW)
            .await
            .expect("one clock must accept the challenge");
    }

    /// The reproduction, and the fix. Nothing differs from the control except
    /// that the phone runs on its own measured second, one behind the desktop's.
    ///
    /// This used to stop at the first line below with `InvalidIssuedAt`, which
    /// `LanRuntimeError::from_challenge_refusal` rendered to the owner as an
    /// expiry. It is not an expiry - the challenge had 239 of its 240 seconds
    /// left - and it is not the replay guard, which budgets 60 seconds of skew
    /// for these identical timestamps. It now runs the whole handshake.
    #[tokio::test]
    async fn one_second_of_skew_completes_the_whole_handshake() {
        let fixture = Fixture::new("wallet_one");
        let desktop = production_challenge(&fixture, DESKTOP_NOW).await;
        let challenge = desktop.challenge();

        // Not expiry: the challenge is alive for another 239 seconds.
        assert!(challenge.expires_at > PHONE_NOW + SESSION_LIFETIME_SECS - 2);
        // Not the replay guard, which budgets 60 seconds of skew for the very
        // same timestamps (crates/companion-protocol/src/replay.rs).
        assert!(challenge.replay_metadata().validate_at(PHONE_NOW).is_ok());
        // The refusal itself, at the line the investigation named.
        assert_eq!(
            challenge.validate_at(PHONE_NOW),
            Ok(()),
            "a one second clock offset must not refuse a live challenge"
        );

        handshake_across_two_clocks(&fixture, DESKTOP_NOW, PHONE_NOW)
            .await
            .expect("one second of clock offset must not refuse a live reconnect");
    }

    /// The whole tolerated range, in both directions, end to end.
    ///
    /// Relaxing only `issued_at > now` would have moved the refusal rather than
    /// ended it: `response_matches` on the desktop compares the phone's
    /// `issued_at` against the challenge's, `confirmation_matches` on the phone
    /// compares the desktop's against the response's, and the phone's derived
    /// response has to fit under the lifetime cap. Each of those is a
    /// two-clock comparison and each is exercised here.
    #[tokio::test]
    async fn every_offset_within_the_budget_completes_in_either_direction() {
        let fixture = Fixture::new("wallet_one");
        for offset in [0, 1, 2, 59, MAX_CLOCK_SKEW_SECS] {
            handshake_across_two_clocks(&fixture, DESKTOP_NOW, DESKTOP_NOW - offset)
                .await
                .unwrap_or_else(|error| {
                    panic!("a desktop {offset}s ahead of its phone was refused: {error:?}")
                });
            handshake_across_two_clocks(&fixture, DESKTOP_NOW, DESKTOP_NOW + offset)
                .await
                .unwrap_or_else(|error| {
                    panic!("a phone {offset}s ahead of its desktop was refused: {error:?}")
                });
        }
    }

    /// The budget is bounded, not removed. One second past it and the challenge
    /// is refused again, as `InvalidIssuedAt` and nothing else - which is what
    /// lets `LanRuntimeError` give that cause its own honest sentence about
    /// clocks instead of borrowing the expiry one.
    #[tokio::test]
    async fn an_offset_past_the_budget_is_still_refused_as_invalid_issued_at() {
        let fixture = Fixture::new("wallet_one");
        let desktop = production_challenge(&fixture, DESKTOP_NOW).await;
        let beyond = DESKTOP_NOW - MAX_CLOCK_SKEW_SECS - 1;
        assert_eq!(
            desktop.challenge().validate_at(beyond),
            Err(CompanionError::InvalidIssuedAt)
        );
        assert_eq!(
            handshake_across_two_clocks(&fixture, DESKTOP_NOW, beyond).await,
            Err(CompanionError::InvalidIssuedAt)
        );
    }

    /// A challenge that has genuinely run out is still refused, and is refused
    /// as `Expired` rather than as the skew cause. The distinction is the copy
    /// fix: these are two different things to tell an owner, and only one of
    /// them is about clocks.
    #[tokio::test]
    async fn a_genuinely_expired_challenge_is_still_refused() {
        let fixture = Fixture::new("wallet_one");
        let desktop = production_challenge(&fixture, DESKTOP_NOW).await;
        let challenge = desktop.challenge();
        let dead = challenge.expires_at;

        assert_eq!(challenge.validate_at(dead), Err(CompanionError::Expired));
        assert_eq!(
            challenge.validate_at(dead + 10_000),
            Err(CompanionError::Expired)
        );
        // The skew budget applies to `issued_at` only. It buys an expired
        // challenge nothing, in either direction.
        assert_eq!(
            challenge.validate_at(dead + MAX_CLOCK_SKEW_SECS),
            Err(CompanionError::Expired)
        );
        assert_eq!(
            handshake_across_two_clocks(&fixture, DESKTOP_NOW, dead).await,
            Err(CompanionError::Expired)
        );
        // Alive one second earlier, so this is the expiry boundary itself and
        // not some other refusal standing in for it.
        assert_eq!(challenge.validate_at(dead - 1), Ok(()));
    }

    /// The anti-replay contract the previous pass established is untouched: the
    /// desktop's `challenge_sequence` is strictly increasing, and a phone that
    /// is offered a sequence it has already consumed still refuses it.
    #[tokio::test]
    async fn a_reoffered_challenge_sequence_is_still_refused_as_a_replay() {
        let fixture = Fixture::new("wallet_one");
        let mut source = DesktopChallengeSequence::new();
        let first_sequence = source.next(0, DESKTOP_NOW).unwrap();
        let second_sequence = source.next(0, DESKTOP_NOW).unwrap();
        assert!(
            second_sequence > first_sequence,
            "the desktop's counter must stay strictly increasing within one second",
        );

        let mut guard = ReplayGuard::new();
        let first = challenge_with_sequence(&fixture, first_sequence, DESKTOP_NOW).await;
        MobileSessionAttempt::respond(
            first.challenge().clone(),
            &fixture.mobile,
            &fixture.registry,
            &mut guard,
            1,
            PHONE_NOW,
        )
        .await
        .expect("the first challenge must be accepted");

        // A rolled-back or rogue desktop reoffering a consumed sequence. Fresh
        // nonce, fresh signature, still inside the clock budget: the only thing
        // wrong with it is the sequence.
        let replayed = challenge_with_sequence(&fixture, first_sequence, DESKTOP_NOW).await;
        assert_ne!(
            replayed.challenge().challenge_nonce,
            first.challenge().challenge_nonce
        );
        assert_eq!(replayed.challenge().validate_at(PHONE_NOW), Ok(()));
        assert_eq!(
            MobileSessionAttempt::respond(
                replayed.challenge().clone(),
                &fixture.mobile,
                &fixture.registry,
                &mut guard,
                2,
                PHONE_NOW,
            )
            .await
            .unwrap_err(),
            CompanionError::SequenceReplay,
        );

        // And the guard is refusing the replay, not the phone: the next
        // strictly greater sequence is still accepted.
        let next = challenge_with_sequence(&fixture, second_sequence, DESKTOP_NOW).await;
        MobileSessionAttempt::respond(
            next.challenge().clone(),
            &fixture.mobile,
            &fixture.registry,
            &mut guard,
            3,
            PHONE_NOW,
        )
        .await
        .expect("a strictly greater challenge sequence must still be accepted");
    }

    /// The second-order blocker, closed structurally rather than by picking two
    /// numbers that happen to fit.
    ///
    /// The phone pins `expires_at` to the challenge's and stamps `issued_at`
    /// with its own clock, so the response it derives is
    /// `requested_lifetime + offset` seconds long. With the requested lifetime
    /// equal to the cap - which is what shipped - one second of offset produced
    /// a 301-second response against a 300-second cap. Reserving the whole skew
    /// budget as headroom makes every offset the protocol tolerates fit.
    #[test]
    fn the_requested_lifetime_leaves_room_for_the_whole_skew_budget() {
        assert!(
            SESSION_LIFETIME_SECS < MAX_HANDSHAKE_LIFETIME_SECS,
            "the requested lifetime must not sit flush against the verification cap",
        );
        assert_eq!(
            SESSION_LIFETIME_SECS + MAX_CLOCK_SKEW_SECS,
            MAX_HANDSHAKE_LIFETIME_SECS,
            "the headroom must be exactly the skew budget: less refuses live \
             handshakes, more shortens sessions for nothing",
        );
        for offset in 0..=MAX_CLOCK_SKEW_SECS {
            let challenge_expires_at = DESKTOP_NOW + SESSION_LIFETIME_SECS;
            let derived_lifetime = challenge_expires_at - (DESKTOP_NOW - offset);
            assert!(
                derived_lifetime <= MAX_HANDSHAKE_LIFETIME_SECS,
                "a phone {offset}s behind derives a {derived_lifetime}s response, over the \
                 {MAX_HANDSHAKE_LIFETIME_SECS}s cap, so it would be refused as malformed",
            );
        }
    }

    /// A desktop cannot ask for a window that would reintroduce the blocker
    /// above, whatever a future caller passes in.
    #[tokio::test]
    async fn a_lifetime_request_above_the_headroom_is_refused_at_the_source() {
        let fixture = Fixture::new("wallet_one");
        assert_eq!(
            DesktopSessionAttempt::start(
                &fixture.desktop,
                &fixture.registry,
                "wallet_one",
                fixture.mobile.device_id().clone(),
                1,
                DESKTOP_NOW,
                MAX_REQUESTED_SESSION_LIFETIME_SECS + 1,
            )
            .await
            .unwrap_err(),
            CompanionError::InvalidSession,
        );
    }
}
