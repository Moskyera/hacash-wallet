#![cfg(feature = "listener")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_wallet_core::{AgentPermission, AgentPolicy, AgentWalletManager, CreateAgentWallet};
use agent_wallet_runtime::{
    AgentWalletRuntime, LocalEndpoint, LocalTransportContext, RuntimeConfig, RuntimeError,
    TransportBindingFactory,
};
use hpay_agent_connector::{
    AgentBackend, AgentIdentityKey, Capability, ConnectorError, ConnectorResult, ErrorCode,
    FrameCodec, PairingAcknowledgement, PairingBearer, PairingClientEnvelope, PairingClientMessage,
    PairingRequest, PairingServerEnvelope, PairingServerMessage, ServerIdentityKey,
    TransportBinding, verify_pairing_completion_receipt,
};

static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(1);
// Each fixture performs a production-strength vault KDF and owns a singleton
// local listener. Running many of them concurrently can exhaust constrained CI
// workers and turn setup into a non-deterministic Vault error.
static PAIRING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct TestBindingFactory;

impl TransportBindingFactory for TestBindingFactory {
    fn create_binding(&self, context: &LocalTransportContext) -> ConnectorResult<TransportBinding> {
        Ok(TransportBinding {
            binding_version: 1,
            transport_kind: context.transport_kind().to_owned(),
            connection_id: context.connection_id().clone(),
            peer_identity_sha256: context.peer_identity_sha256().to_owned(),
            transport_transcript_sha256: "cd".repeat(32),
        })
    }
}

struct PairingFixture {
    runtime: AgentWalletRuntime,
    wallet_id: agent_wallet_core::AgentWalletId,
    root: std::path::PathBuf,
    _serial_guard: std::sync::MutexGuard<'static, ()>,
}

impl PairingFixture {
    fn new(label: &str) -> Self {
        let serial_guard = PAIRING_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = std::env::temp_dir().join(format!(
            "hpay-pairing-runtime-{label}-{}-{}",
            std::process::id(),
            NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let now = unix_now();
        let mut manager = AgentWalletManager::open(&root).unwrap();
        let created = manager
            .create_wallet(
                CreateAgentWallet {
                    passphrase: "correct horse battery staple".to_owned(),
                    network_mode: "testnet".to_owned(),
                    node_url: "http://127.0.0.1:18081".to_owned(),
                    block_one_fingerprint: Some(
                        "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff"
                            .to_owned(),
                    ),
                },
                now,
            )
            .unwrap();
        manager
            .unlock(&created.wallet_id, "correct horse battery staple", now)
            .unwrap();
        let (desktop_instance_id, server_identity_key) = manager
            .connector_server_identity(&created.wallet_id, now)
            .unwrap();
        let runtime = AgentWalletRuntime::new(
            manager,
            created.wallet_id.clone(),
            runtime_config(desktop_instance_id, &root),
            server_identity_key,
            Arc::new(TestBindingFactory),
        )
        .unwrap();
        runtime.start().unwrap();
        Self {
            runtime,
            wallet_id: created.wallet_id,
            root,
            _serial_guard: serial_guard,
        }
    }

    fn endpoint(&self) -> String {
        self.runtime.status().endpoint.unwrap()
    }

    fn finish(self) {
        self.runtime.stop().unwrap();
        drop(self.runtime);
        std::fs::remove_dir_all(self.root).unwrap();
    }
}

fn runtime_config(desktop_instance_id: String, _root: &std::path::Path) -> RuntimeConfig {
    RuntimeConfig {
        desktop_instance_id,
        endpoint: {
            #[cfg(windows)]
            {
                LocalEndpoint::WindowsNamedPipe {
                    instance_suffix: format!(
                        "{:016x}{:016x}",
                        std::process::id(),
                        NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed)
                    ),
                }
            }
            #[cfg(unix)]
            {
                LocalEndpoint::UnixDomainSocket {
                    socket_path: _root.join("agent.sock"),
                }
            }
        },
        max_frame_bytes: hpay_agent_connector::MAX_FRAME_BYTES,
        accept_timeout: Duration::from_millis(20),
        read_timeout: Duration::from_millis(250),
        write_timeout: Duration::from_millis(250),
        dispatch_timeout: Duration::from_millis(500),
        startup_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(1),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn bearer(pairing_id: &str) -> PairingBearer {
    PairingBearer::parse(pairing_id.to_owned()).unwrap()
}

fn request(
    pairing_id: &str,
    identity: &AgentIdentityKey,
    capabilities: impl IntoIterator<Item = Capability>,
) -> PairingClientEnvelope {
    PairingClientEnvelope::submit(PairingRequest {
        pairing_id: bearer(pairing_id),
        agent_name: "Local Assistant".to_owned(),
        agent_version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: identity.public_key_sec1_hex(),
        requested_capabilities: capabilities.into_iter().collect(),
    })
    .unwrap()
}

fn policy(capabilities: impl IntoIterator<Item = AgentPermission>) -> AgentPolicy {
    AgentPolicy {
        permissions: capabilities.into_iter().collect(),
        ..AgentPolicy::default()
    }
}

fn exchange(endpoint: &str, envelope: &PairingClientEnvelope) -> PairingServerEnvelope {
    let codec = FrameCodec::default();
    let payload = envelope.to_payload().unwrap();
    #[cfg(windows)]
    let response_payload = {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut pipe = loop {
            match hpay_agent_connector::transport::windows::open_protocol_client(endpoint) {
                Ok(pipe) => break pipe,
                Err(_error) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("pairing pipe did not become available: {error}"),
            }
        };
        codec.write_to(&mut pipe, &payload).unwrap();
        let response_payload = codec.read_from(&mut pipe).unwrap();
        let response = PairingServerEnvelope::from_payload(&response_payload).unwrap();
        let acknowledgement =
            PairingAcknowledgement::for_response_payload(response.request_id, &response_payload)
                .unwrap();
        codec
            .write_to(&mut pipe, &acknowledgement.to_payload().unwrap())
            .unwrap();
        response_payload
    };
    #[cfg(unix)]
    let response_payload = {
        let mut stream = std::os::unix::net::UnixStream::connect(endpoint).unwrap();
        codec.write_to(&mut stream, &payload).unwrap();
        let response_payload = codec.read_from(&mut stream).unwrap();
        let response = PairingServerEnvelope::from_payload(&response_payload).unwrap();
        let acknowledgement =
            PairingAcknowledgement::for_response_payload(response.request_id, &response_payload)
                .unwrap();
        codec
            .write_to(&mut stream, &acknowledgement.to_payload().unwrap())
            .unwrap();
        response_payload
    };
    PairingServerEnvelope::from_payload(&response_payload).unwrap()
}

fn assert_error(response: PairingServerEnvelope, expected: ErrorCode) {
    let PairingServerMessage::Error(error) = response.payload else {
        panic!("expected pairing error response");
    };
    assert_eq!(error.code, expected);
}

#[tokio::test(flavor = "current_thread")]
async fn valid_pairing_returns_idempotent_and_fresh_nonce_receipts() {
    let fixture = PairingFixture::new("valid");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 3)
        .await
        .unwrap();
    let identity = AgentIdentityKey::generate();
    let response = exchange(
        &fixture.endpoint(),
        &request(
            activation.pairing_id(),
            &identity,
            [Capability::ReadBalance, Capability::ReadWalletInfo],
        ),
    );
    let PairingServerMessage::Pending(submission) = response.payload else {
        panic!("expected pending pairing");
    };
    let pending = fixture.runtime.pending_pairing().unwrap().unwrap();
    assert_eq!(pending.wallet_id, fixture.wallet_id);
    assert_eq!(pending.identity_fingerprint, identity.fingerprint());
    assert_eq!(
        pending.submission_commitment,
        submission.submission_commitment
    );

    let record = fixture
        .runtime
        .approve_pairing(
            activation.pairing_id(),
            &submission.submission_commitment,
            policy([Capability::ReadBalance]),
        )
        .await
        .unwrap();
    let completion_envelope = PairingClientEnvelope::completion(
        bearer(activation.pairing_id()),
        submission.submission_commitment.clone(),
        &identity,
    )
    .unwrap();
    let PairingClientMessage::Completion(completion_request) = &completion_envelope.payload else {
        panic!("expected completion request");
    };
    let completion_response = exchange(&fixture.endpoint(), &completion_envelope);
    let PairingServerMessage::Completed(receipt) = completion_response.payload else {
        panic!("expected signed completion receipt");
    };
    verify_pairing_completion_receipt(
        &receipt,
        completion_request,
        activation.server_identity(),
        unix_now(),
    )
    .unwrap();
    assert_eq!(receipt.agent_id, record.agent_id);
    assert_eq!(receipt.wallet_id, fixture.wallet_id);
    assert_eq!(receipt.capabilities, record.policy.permissions);

    let exact_retry = exchange(&fixture.endpoint(), &completion_envelope);
    assert_eq!(
        exact_retry.payload,
        PairingServerMessage::Completed(receipt.clone())
    );
    let second_completion = PairingClientEnvelope::completion(
        bearer(activation.pairing_id()),
        submission.submission_commitment,
        &identity,
    )
    .unwrap();
    let PairingClientMessage::Completion(second_request) = &second_completion.payload else {
        panic!("expected second completion request");
    };
    let second_response = exchange(&fixture.endpoint(), &second_completion);
    let PairingServerMessage::Completed(second_receipt) = second_response.payload else {
        panic!("fresh signed nonce must recover the same durable authorization");
    };
    verify_pairing_completion_receipt(
        &second_receipt,
        second_request,
        activation.server_identity(),
        unix_now(),
    )
    .unwrap();
    assert_eq!(second_receipt.agent_id, receipt.agent_id);
    assert_eq!(
        second_receipt.authorization_epoch,
        receipt.authorization_epoch
    );
    assert_ne!(second_receipt.client_nonce, receipt.client_nonce);

    let manager = fixture.runtime.manager();
    let paired = manager
        .lock()
        .await
        .paired_agent(&record.agent_id, &fixture.wallet_id)
        .await
        .unwrap();
    assert_eq!(paired.agent_id, record.agent_id);
    assert_eq!(paired.identity_fingerprint, record.identity_fingerprint);
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn completion_survives_manager_reopen_and_rejects_a_wrong_runtime_key() {
    let fixture = PairingFixture::new("durable-reopen");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 3)
        .await
        .unwrap();
    let identity = AgentIdentityKey::generate();
    let PairingServerMessage::Pending(pending) = exchange(
        &fixture.endpoint(),
        &request(
            activation.pairing_id(),
            &identity,
            [Capability::ReadBalance],
        ),
    )
    .payload
    else {
        panic!("expected pending pairing");
    };
    let pairing_id = activation.pairing_id().to_owned();
    let commitment = pending.submission_commitment.clone();
    let pinned_server = activation.server_identity().clone();
    let record = fixture
        .runtime
        .approve_pairing(&pairing_id, &commitment, policy([Capability::ReadBalance]))
        .await
        .unwrap();

    fixture.runtime.stop().unwrap();
    let PairingFixture {
        runtime,
        wallet_id,
        root,
        _serial_guard,
    } = fixture;
    drop(runtime);

    let now = unix_now();
    let mut wrong_manager = AgentWalletManager::open(&root).unwrap();
    wrong_manager
        .unlock(&wallet_id, "correct horse battery staple", now)
        .unwrap();
    let (desktop_instance_id, _) = wrong_manager
        .connector_server_identity(&wallet_id, now)
        .unwrap();
    assert!(matches!(
        AgentWalletRuntime::new(
            wrong_manager,
            wallet_id.clone(),
            runtime_config(desktop_instance_id, &root),
            ServerIdentityKey::generate(),
            Arc::new(TestBindingFactory),
        ),
        Err(RuntimeError::ServerIdentityMismatch)
    ));

    let mut reopened_manager = AgentWalletManager::open(&root).unwrap();
    reopened_manager
        .unlock(&wallet_id, "correct horse battery staple", now)
        .unwrap();
    let (desktop_instance_id, server_identity_key) = reopened_manager
        .connector_server_identity(&wallet_id, now)
        .unwrap();
    let reopened = AgentWalletRuntime::new(
        reopened_manager,
        wallet_id.clone(),
        runtime_config(desktop_instance_id, &root),
        server_identity_key,
        Arc::new(TestBindingFactory),
    )
    .unwrap();
    assert_eq!(reopened.pinned_server_identity().unwrap(), pinned_server);
    reopened.start().unwrap();

    let completion =
        PairingClientEnvelope::completion(bearer(&pairing_id), commitment, &identity).unwrap();
    let PairingClientMessage::Completion(completion_request) = &completion.payload else {
        panic!("expected completion request");
    };
    let PairingServerMessage::Completed(receipt) =
        exchange(&reopened.status().endpoint.unwrap(), &completion).payload
    else {
        panic!("durable completion missing after manager reopen");
    };
    verify_pairing_completion_receipt(&receipt, completion_request, &pinned_server, unix_now())
        .unwrap();
    assert_eq!(receipt.agent_id, record.agent_id);
    let reopened_manager = reopened.manager();
    let agent_count = reopened_manager
        .try_lock()
        .expect("worker must release the manager after completion")
        .list_agents_admin(&wallet_id, unix_now())
        .unwrap()
        .len();
    assert_eq!(
        agent_count, 1,
        "completion recovery must not register a second agent"
    );
    reopened.stop().unwrap();
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
    drop(_serial_guard);
}

#[tokio::test(flavor = "current_thread")]
async fn rejection_consumes_the_pairing_and_reuse_fails_closed() {
    let fixture = PairingFixture::new("reject");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 2)
        .await
        .unwrap();
    let envelope = request(
        activation.pairing_id(),
        &AgentIdentityKey::generate(),
        [Capability::ReadBalance],
    );
    assert!(matches!(
        exchange(&fixture.endpoint(), &envelope).payload,
        PairingServerMessage::Pending(_)
    ));
    let commitment = fixture
        .runtime
        .pending_pairing()
        .unwrap()
        .unwrap()
        .submission_commitment;
    fixture
        .runtime
        .reject_pairing(activation.pairing_id(), &commitment)
        .unwrap();
    assert_error(
        exchange(&fixture.endpoint(), &envelope),
        ErrorCode::PairingInactive,
    );
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn expired_pairing_is_not_visible_or_usable() {
    let fixture = PairingFixture::new("expired");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 1, 2)
        .await
        .unwrap();
    while unix_now() < activation.expires_at_unix() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(fixture.runtime.pending_pairing().unwrap().is_none());
    assert_error(
        exchange(
            &fixture.endpoint(),
            &request(
                activation.pairing_id(),
                &AgentIdentityKey::generate(),
                [Capability::ReadBalance],
            ),
        ),
        ErrorCode::PairingInactive,
    );
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_pairing_id_is_rejected_without_replacing_the_active_session() {
    let fixture = PairingFixture::new("wrong-id");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 3)
        .await
        .unwrap();
    let identity = AgentIdentityKey::generate();
    assert_error(
        exchange(
            &fixture.endpoint(),
            &request(
                &format!("pair_{}", "ab".repeat(32)),
                &identity,
                [Capability::ReadBalance],
            ),
        ),
        ErrorCode::AuthenticationFailed,
    );
    assert!(matches!(
        exchange(
            &fixture.endpoint(),
            &request(
                activation.pairing_id(),
                &identity,
                [Capability::ReadBalance],
            ),
        )
        .payload,
        PairingServerMessage::Pending(_)
    ));
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn successful_pairing_cannot_be_submitted_or_approved_twice() {
    let fixture = PairingFixture::new("single-use");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 2)
        .await
        .unwrap();
    let envelope = request(
        activation.pairing_id(),
        &AgentIdentityKey::generate(),
        [Capability::ReadBalance],
    );
    exchange(&fixture.endpoint(), &envelope);
    let commitment = fixture
        .runtime
        .pending_pairing()
        .unwrap()
        .unwrap()
        .submission_commitment;
    fixture
        .runtime
        .approve_pairing(
            activation.pairing_id(),
            &commitment,
            policy([Capability::ReadBalance]),
        )
        .await
        .unwrap();
    assert_error(
        exchange(&fixture.endpoint(), &envelope),
        ErrorCode::PairingInactive,
    );
    assert_eq!(
        fixture
            .runtime
            .approve_pairing(
                activation.pairing_id(),
                &commitment,
                policy([Capability::ReadBalance]),
            )
            .await
            .unwrap_err(),
        RuntimeError::Connector(ConnectorError::PairingInactive)
    );
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn approval_policy_cannot_escalate_requested_capabilities() {
    let fixture = PairingFixture::new("escalation");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 2)
        .await
        .unwrap();
    exchange(
        &fixture.endpoint(),
        &request(
            activation.pairing_id(),
            &AgentIdentityKey::generate(),
            [Capability::ReadBalance],
        ),
    );
    let commitment = fixture
        .runtime
        .pending_pairing()
        .unwrap()
        .unwrap()
        .submission_commitment;
    assert_eq!(
        fixture
            .runtime
            .approve_pairing(
                activation.pairing_id(),
                &commitment,
                policy([Capability::ReadBalance, Capability::CreatePaymentIntent,]),
            )
            .await
            .unwrap_err(),
        RuntimeError::Connector(ConnectorError::CapabilityDenied)
    );
    assert!(fixture.runtime.pending_pairing().unwrap().is_none());
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn client_submission_without_an_active_runtime_pairing_is_rejected() {
    let fixture = PairingFixture::new("inactive");
    assert_error(
        exchange(
            &fixture.endpoint(),
            &request(
                &format!("pair_{}", "cd".repeat(32)),
                &AgentIdentityKey::generate(),
                [Capability::ReadBalance],
            ),
        ),
        ErrorCode::PairingInactive,
    );
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn attempt_limit_consumes_the_session_and_clears_stale_pending() {
    let fixture = PairingFixture::new("attempt-limit");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 1)
        .await
        .unwrap();
    let identity = AgentIdentityKey::generate();
    assert_error(
        exchange(
            &fixture.endpoint(),
            &request(
                &format!("pair_{}", "ef".repeat(32)),
                &identity,
                [Capability::ReadBalance],
            ),
        ),
        ErrorCode::AuthenticationFailed,
    );
    let exhausted = exchange(
        &fixture.endpoint(),
        &request(
            activation.pairing_id(),
            &identity,
            [Capability::ReadBalance],
        ),
    );
    let PairingServerMessage::Error(error) = exhausted.payload else {
        panic!("expected exhausted pairing error");
    };
    assert_eq!(error.code, ErrorCode::PairingAttemptsExceeded);
    assert!(!error.retryable);
    assert!(fixture.runtime.pending_pairing().unwrap().is_none());
    assert_error(
        exchange(
            &fixture.endpoint(),
            &request(
                activation.pairing_id(),
                &identity,
                [Capability::ReadBalance],
            ),
        ),
        ErrorCode::PairingInactive,
    );
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn identity_swap_and_wrong_approval_commitment_fail_without_replacing_pending() {
    let fixture = PairingFixture::new("identity-swap");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 3)
        .await
        .unwrap();
    let first_identity = AgentIdentityKey::generate();
    let second_identity = AgentIdentityKey::generate();
    let first_envelope = request(
        activation.pairing_id(),
        &first_identity,
        [Capability::ReadBalance],
    );
    exchange(&fixture.endpoint(), &first_envelope);
    let first_pending = fixture.runtime.pending_pairing().unwrap().unwrap();
    let second_envelope = request(
        activation.pairing_id(),
        &second_identity,
        [Capability::ReadBalance],
    );
    let PairingClientMessage::Submit(second_request) = &second_envelope.payload else {
        panic!("expected submit request");
    };
    let second_commitment = second_request.submission_commitment().unwrap();
    assert_error(
        exchange(&fixture.endpoint(), &second_envelope),
        ErrorCode::AuthenticationFailed,
    );
    assert_eq!(
        fixture
            .runtime
            .pending_pairing()
            .unwrap()
            .unwrap()
            .identity_fingerprint,
        first_identity.fingerprint()
    );
    assert_eq!(
        fixture
            .runtime
            .approve_pairing(
                activation.pairing_id(),
                &second_commitment,
                policy([Capability::ReadBalance]),
            )
            .await
            .unwrap_err(),
        RuntimeError::Connector(ConnectorError::AuthenticationFailed)
    );
    let record = fixture
        .runtime
        .approve_pairing(
            activation.pairing_id(),
            &first_pending.submission_commitment,
            policy([Capability::ReadBalance]),
        )
        .await
        .unwrap();
    assert_eq!(record.identity_fingerprint, first_identity.fingerprint());
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn stop_clears_pairing_and_old_bearer_cannot_cross_restart() {
    let fixture = PairingFixture::new("stop-race");
    let activation = fixture
        .runtime
        .activate_pairing(fixture.wallet_id.clone(), 60, 2)
        .await
        .unwrap();
    let envelope = request(
        activation.pairing_id(),
        &AgentIdentityKey::generate(),
        [Capability::ReadBalance],
    );
    exchange(&fixture.endpoint(), &envelope);
    assert!(fixture.runtime.pending_pairing().unwrap().is_some());
    fixture.runtime.stop().unwrap();
    assert!(fixture.runtime.pending_pairing().unwrap().is_none());
    fixture.runtime.start().unwrap();
    assert_error(
        exchange(&fixture.endpoint(), &envelope),
        ErrorCode::PairingInactive,
    );
    fixture.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn stop_joins_a_worker_blocked_on_a_silent_client() {
    let fixture = PairingFixture::new("silent-stop");
    let endpoint = fixture.endpoint();

    #[cfg(windows)]
    let silent_client =
        hpay_agent_connector::transport::windows::open_protocol_client(&endpoint).unwrap();
    #[cfg(unix)]
    let silent_client = std::os::unix::net::UnixStream::connect(&endpoint).unwrap();

    // Give the worker enough time to accept the authenticated local peer and
    // enter its bounded frame read before requesting shutdown.
    std::thread::sleep(Duration::from_millis(30));
    let started = Instant::now();
    fixture.runtime.stop().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "stop must join the worker instead of detaching a blocked connection"
    );
    assert_eq!(
        fixture.runtime.status().phase,
        agent_wallet_runtime::RuntimePhase::Stopped
    );

    drop(silent_client);
    #[cfg(windows)]
    assert!(
        hpay_agent_connector::transport::windows::open_protocol_client(&endpoint).is_err(),
        "stopped runtime must not leave a named-pipe listener behind"
    );
    #[cfg(unix)]
    assert!(
        std::os::unix::net::UnixStream::connect(&endpoint).is_err(),
        "stopped runtime must not leave a Unix socket listener behind"
    );

    let PairingFixture {
        runtime,
        wallet_id: _,
        root,
        _serial_guard,
    } = fixture;
    drop(runtime);
    std::fs::remove_dir_all(root).unwrap();
    drop(_serial_guard);
}
