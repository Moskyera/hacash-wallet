use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hpay_companion_protocol::{CompanionMessage, DeviceId, SessionChallenge, SessionConfirmation};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::backend::{AuthenticatedSession, MobileSessionBackend};
use crate::config::validate_remote_endpoint;
use crate::error::{LanRuntimeError, LanRuntimeResult};
use crate::framing::{PacketKind, read_packet, write_packet};
use crate::wire::{decode_encrypted_frame, encode_client_hello, encode_encrypted_frame};

pub struct MobileLanSession {
    stream: TcpStream,
    authenticated: AuthenticatedSession,
    io_timeout: Duration,
    idle_timeout: Duration,
    backend: Arc<dyn MobileSessionBackend>,
}

impl std::fmt::Debug for MobileLanSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MobileLanSession")
            .field("connection", &self.authenticated.connection)
            .field("stream", &"<private-lan>")
            .finish()
    }
}

impl MobileLanSession {
    pub async fn connect(
        endpoint: SocketAddr,
        mobile_device_id: DeviceId,
        backend: Arc<dyn MobileSessionBackend>,
    ) -> LanRuntimeResult<Self> {
        Self::connect_with_policy(endpoint, mobile_device_id, backend, false).await
    }

    async fn connect_with_policy(
        endpoint: SocketAddr,
        mobile_device_id: DeviceId,
        backend: Arc<dyn MobileSessionBackend>,
        allow_test_loopback: bool,
    ) -> LanRuntimeResult<Self> {
        validate_remote_endpoint(endpoint, allow_test_loopback)?;
        let handshake_timeout = Duration::from_secs(10);
        let io_timeout = Duration::from_secs(10);
        let idle_timeout = Duration::from_secs(60);
        let mut stream = timeout(handshake_timeout, TcpStream::connect(endpoint))
            .await
            .map_err(|_| LanRuntimeError::Timeout)??;
        stream.set_nodelay(true)?;
        write_packet(
            &mut stream,
            PacketKind::ClientHello,
            &encode_client_hello(&mobile_device_id),
            io_timeout,
        )
        .await?;
        let challenge = read_packet(&mut stream, handshake_timeout)
            .await
            .map_err(|error| error.at_stage(LanRuntimeError::EofDuringDeviceAuthentication))?;
        if challenge.kind != PacketKind::SessionChallenge {
            return Err(LanRuntimeError::MalformedFrame);
        }
        let challenge = SessionChallenge::from_bytes(&challenge.body)?;
        if challenge.mobile_device_id != mobile_device_id {
            return Err(LanRuntimeError::ChallengeAddressedToAnotherDevice);
        }
        let now = unix_now()?;
        let attempt = backend.respond(challenge, now).await?;
        write_packet(
            &mut stream,
            PacketKind::SessionResponse,
            &attempt.response().to_bytes()?,
            io_timeout,
        )
        .await?;
        let confirmation = read_packet(&mut stream, handshake_timeout)
            .await
            .map_err(|error| error.at_stage(LanRuntimeError::EofDuringSessionKeyConfirmation))?;
        if confirmation.kind != PacketKind::SessionConfirmation {
            return Err(LanRuntimeError::MalformedFrame);
        }
        let confirmation = SessionConfirmation::from_bytes(&confirmation.body)?;
        let now = unix_now()?;
        let established = attempt.verify(confirmation, now).await?;
        let authenticated = AuthenticatedSession::from_mobile(established, now)?;
        Ok(Self {
            stream,
            authenticated,
            io_timeout,
            idle_timeout,
            backend,
        })
    }

    pub fn connection(&self) -> &hpay_companion_protocol::CompanionConnection {
        &self.authenticated.connection
    }

    pub async fn send(&mut self, message: &CompanionMessage) -> LanRuntimeResult<()> {
        let now = unix_now()?;
        self.authenticated.connection.validate_at(now)?;
        let frame = self.authenticated.cipher.encrypt(message, now)?;
        let encoded = encode_encrypted_frame(&frame)?;
        write_packet(
            &mut self.stream,
            PacketKind::EncryptedFrame,
            &encoded,
            self.io_timeout,
        )
        .await
    }

    pub async fn receive(&mut self) -> LanRuntimeResult<CompanionMessage> {
        let packet = read_packet(&mut self.stream, self.idle_timeout)
            .await
            .map_err(|error| error.at_stage(LanRuntimeError::EofDuringAuthenticatedSession))?;
        if packet.kind != PacketKind::EncryptedFrame {
            return Err(LanRuntimeError::DowngradeAttempt);
        }
        let frame = decode_encrypted_frame(&packet.body)?;
        let now = unix_now()?;
        self.authenticated.connection.validate_at(now)?;
        let (message, replay) = self.authenticated.cipher.decrypt(&frame, now)?;
        self.backend
            .accept_message(&self.authenticated.connection, message, replay, now)
            .await
    }

    pub async fn disconnect(mut self) -> LanRuntimeResult<()> {
        timeout(self.io_timeout, self.stream.shutdown())
            .await
            .map_err(|_| LanRuntimeError::Timeout)??;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn connect_loopback_for_tests(
        endpoint: SocketAddr,
        mobile_device_id: DeviceId,
        backend: Arc<dyn MobileSessionBackend>,
    ) -> LanRuntimeResult<Self> {
        Self::connect_with_policy(endpoint, mobile_device_id, backend, true).await
    }
}

fn unix_now() -> LanRuntimeResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| LanRuntimeError::Task)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use hpay_companion_protocol::{
        CompanionConnection, CompanionPayload, DesktopSessionAttempt, DeviceRegistry, DeviceRole,
        EstablishedSession, MobileSessionAttempt, PROTOCOL_VERSION, ReplayGuard, ReplayMetadata,
        SessionConfirmation, SessionResponse, SoftwareDeviceIdentity,
    };
    use tokio::sync::{Mutex, Notify};

    use super::*;
    use crate::backend::{
        DesktopHandshake, DesktopSessionBackend, HandleMessageResult, MobileHandshake,
        RuntimeFuture,
    };
    use crate::config::{LanRuntimeConfig, RuntimeGateController, RuntimeStartupGate};
    use crate::framing::{PacketKind, write_packet};
    use crate::server::DesktopLanServer;

    struct DesktopBackend {
        signer: Arc<SoftwareDeviceIdentity>,
        registry: DeviceRegistry,
        replay: Arc<Mutex<ReplayGuard>>,
        sequence: AtomicU64,
        received: Arc<StdMutex<Vec<CompanionMessage>>>,
    }

    struct DesktopAttempt {
        inner: DesktopSessionAttempt,
        signer: Arc<SoftwareDeviceIdentity>,
        registry: DeviceRegistry,
        replay: Arc<Mutex<ReplayGuard>>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum BlockedBackendPhase {
        Begin,
        Accept,
        HandleMessage,
    }

    #[derive(Clone, Copy)]
    enum CancellationSignal {
        Gate,
        Shutdown,
    }

    struct BlockedBackendState {
        entered: Notify,
        release: Notify,
        completed: AtomicBool,
    }

    impl BlockedBackendState {
        fn new() -> Self {
            Self {
                entered: Notify::new(),
                release: Notify::new(),
                completed: AtomicBool::new(false),
            }
        }

        async fn block(&self) {
            self.entered.notify_one();
            self.release.notified().await;
            self.completed.store(true, Ordering::SeqCst);
        }

        async fn wait_until_entered(&self) {
            timeout(Duration::from_secs(1), self.entered.notified())
                .await
                .expect("blocked backend phase was not reached");
        }

        fn release(&self) {
            self.release.notify_waiters();
        }

        fn completed(&self) -> bool {
            self.completed.load(Ordering::SeqCst)
        }
    }

    struct BlockingDesktopBackend {
        inner: Arc<DesktopBackend>,
        phase: BlockedBackendPhase,
        state: Arc<BlockedBackendState>,
    }

    struct BlockingDesktopAttempt {
        inner: Box<dyn DesktopHandshake>,
        phase: BlockedBackendPhase,
        state: Arc<BlockedBackendState>,
    }

    impl DesktopHandshake for BlockingDesktopAttempt {
        fn challenge(&self) -> &SessionChallenge {
            self.inner.challenge()
        }

        fn accept(
            self: Box<Self>,
            response: SessionResponse,
            now: u64,
        ) -> RuntimeFuture<'static, (SessionConfirmation, EstablishedSession)> {
            let Self {
                inner,
                phase,
                state,
            } = *self;
            Box::pin(async move {
                if phase == BlockedBackendPhase::Accept {
                    state.block().await;
                }
                inner.accept(response, now).await
            })
        }
    }

    impl DesktopSessionBackend for BlockingDesktopBackend {
        fn begin<'a>(
            &'a self,
            mobile_device_id: DeviceId,
            now: u64,
        ) -> RuntimeFuture<'a, Box<dyn DesktopHandshake>> {
            Box::pin(async move {
                if self.phase == BlockedBackendPhase::Begin {
                    self.state.block().await;
                }
                let inner = self.inner.begin(mobile_device_id, now).await?;
                Ok(Box::new(BlockingDesktopAttempt {
                    inner,
                    phase: self.phase,
                    state: Arc::clone(&self.state),
                }) as Box<dyn DesktopHandshake>)
            })
        }

        fn handle_message<'a>(
            &'a self,
            connection: &'a CompanionConnection,
            message: CompanionMessage,
            replay: ReplayMetadata,
            now: u64,
        ) -> RuntimeFuture<'a, HandleMessageResult> {
            Box::pin(async move {
                if self.phase == BlockedBackendPhase::HandleMessage {
                    self.state.block().await;
                }
                self.inner
                    .handle_message(connection, message, replay, now)
                    .await
            })
        }
    }

    impl DesktopHandshake for DesktopAttempt {
        fn challenge(&self) -> &SessionChallenge {
            self.inner.challenge()
        }

        fn accept(
            self: Box<Self>,
            response: SessionResponse,
            now: u64,
        ) -> RuntimeFuture<'static, (SessionConfirmation, EstablishedSession)> {
            Box::pin(async move {
                let mut inner = self.inner;
                let mut replay = self.replay.lock().await;
                Ok(inner
                    .accept_response(
                        &response,
                        self.signer.as_ref(),
                        &self.registry,
                        &mut replay,
                        now,
                    )
                    .await?)
            })
        }
    }

    impl DesktopSessionBackend for DesktopBackend {
        fn begin<'a>(
            &'a self,
            mobile_device_id: DeviceId,
            now: u64,
        ) -> RuntimeFuture<'a, Box<dyn DesktopHandshake>> {
            Box::pin(async move {
                let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
                let inner = DesktopSessionAttempt::start(
                    self.signer.as_ref(),
                    &self.registry,
                    "wallet_one",
                    mobile_device_id,
                    sequence,
                    now,
                    30,
                )
                .await?;
                Ok(Box::new(DesktopAttempt {
                    inner,
                    signer: Arc::clone(&self.signer),
                    registry: self.registry.clone(),
                    replay: Arc::clone(&self.replay),
                }) as Box<dyn DesktopHandshake>)
            })
        }

        fn handle_message<'a>(
            &'a self,
            connection: &'a CompanionConnection,
            message: CompanionMessage,
            replay: ReplayMetadata,
            now: u64,
        ) -> RuntimeFuture<'a, HandleMessageResult> {
            Box::pin(async move {
                let mut guard = self.replay.lock().await;
                let permit = guard.check(&replay, now)?;
                guard.commit(permit, now)?;
                self.received.lock().unwrap().push(message.clone());
                let response = match message.payload {
                    CompanionPayload::Ping => Some(CompanionMessage {
                        protocol_version: PROTOCOL_VERSION,
                        message_id: format!("reply_{}", message.message_id),
                        session_id: connection.session_id.clone(),
                        sender_device_id: connection.local_device_id.clone(),
                        recipient_device_id: connection.remote_device_id.clone(),
                        sequence: message.sequence,
                        issued_at: now,
                        expires_at: connection.expires_at,
                        payload: CompanionPayload::Pong,
                    }),
                    _ => None,
                };
                Ok(HandleMessageResult { response })
            })
        }
    }

    struct MobileBackend {
        signer: Arc<SoftwareDeviceIdentity>,
        registry: DeviceRegistry,
        replay: Arc<Mutex<ReplayGuard>>,
        sequence: AtomicU64,
    }

    struct MobileAttempt {
        inner: MobileSessionAttempt,
        registry: DeviceRegistry,
    }

    impl MobileHandshake for MobileAttempt {
        fn response(&self) -> &SessionResponse {
            self.inner.response()
        }

        fn verify(
            self: Box<Self>,
            confirmation: SessionConfirmation,
            now: u64,
        ) -> RuntimeFuture<'static, EstablishedSession> {
            Box::pin(async move {
                Ok(self
                    .inner
                    .verify_confirmation(&confirmation, &self.registry, now)?)
            })
        }
    }

    impl MobileSessionBackend for MobileBackend {
        fn respond<'a>(
            &'a self,
            challenge: SessionChallenge,
            now: u64,
        ) -> RuntimeFuture<'a, Box<dyn MobileHandshake>> {
            Box::pin(async move {
                let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
                let mut replay = self.replay.lock().await;
                let inner = MobileSessionAttempt::respond(
                    challenge,
                    self.signer.as_ref(),
                    &self.registry,
                    &mut replay,
                    sequence,
                    now,
                )
                .await?;
                Ok(Box::new(MobileAttempt {
                    inner,
                    registry: self.registry.clone(),
                }) as Box<dyn MobileHandshake>)
            })
        }

        fn accept_message<'a>(
            &'a self,
            _connection: &'a CompanionConnection,
            message: CompanionMessage,
            replay: ReplayMetadata,
            now: u64,
        ) -> RuntimeFuture<'a, CompanionMessage> {
            Box::pin(async move {
                let mut guard = self.replay.lock().await;
                let permit = guard.check(&replay, now)?;
                guard.commit(permit, now)?;
                Ok(message)
            })
        }
    }

    type FixtureParts = (
        Arc<DesktopBackend>,
        Arc<MobileBackend>,
        DeviceId,
        Arc<StdMutex<Vec<CompanionMessage>>>,
    );

    fn fixture() -> FixtureParts {
        let desktop = Arc::new(SoftwareDeviceIdentity::generate(DeviceRole::Desktop));
        let mobile = Arc::new(SoftwareDeviceIdentity::generate(DeviceRole::Mobile));
        let mut registry = DeviceRegistry::new();
        registry
            .register(
                desktop
                    .public_record("wallet_one", BTreeSet::new(), 1)
                    .unwrap(),
            )
            .unwrap();
        registry
            .register(
                mobile
                    .public_record("wallet_one", BTreeSet::new(), 1)
                    .unwrap(),
            )
            .unwrap();
        let received = Arc::new(StdMutex::new(Vec::new()));
        let desktop_backend = Arc::new(DesktopBackend {
            signer: desktop,
            registry: registry.clone(),
            replay: Arc::new(Mutex::new(ReplayGuard::new())),
            sequence: AtomicU64::new(0),
            received: Arc::clone(&received),
        });
        let mobile_id = mobile.device_id().clone();
        let mobile_backend = Arc::new(MobileBackend {
            signer: mobile,
            registry,
            replay: Arc::new(Mutex::new(ReplayGuard::new())),
            sequence: AtomicU64::new(0),
        });
        (desktop_backend, mobile_backend, mobile_id, received)
    }

    /// The desktop refuses a device it does not recognise by dropping the socket
    /// before its first write: an unknown or stale device id, or a pairing that
    /// was never finalized on the desktop. On a real phone that arrived as a bare
    /// "companion LAN I/O failed: early eof", which reads like a network fault
    /// and hides the only action that fixes it. The stage has to survive.
    #[tokio::test]
    async fn desktop_refusing_the_device_is_reported_as_the_authentication_stage() {
        let (_desktop, mobile_backend, mobile_id, _received) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let refuser = tokio::spawn(async move {
            // Accept, read the ClientHello, then close writing nothing. This is
            // exactly what handle_connection does when begin() rejects.
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut discard = [0_u8; 64];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut discard).await;
            drop(stream);
        });

        let result =
            MobileLanSession::connect_loopback_for_tests(address, mobile_id, mobile_backend).await;
        refuser.await.unwrap();

        match result {
            Err(LanRuntimeError::EofDuringDeviceAuthentication) => {}
            Err(other) => panic!("expected the authentication stage, got {other:?}"),
            Ok(_) => panic!("a silent close must never authenticate"),
        }
        // The owner-facing text has to name the action that resolves it.
        let message = LanRuntimeError::EofDuringDeviceAuthentication.to_string();
        assert!(message.contains("refused this device"), "{message}");
        assert!(
            message.contains("Finish pairing on the desktop"),
            "{message}"
        );
        assert!(!message.contains("early eof"), "{message}");
    }

    /// Only an end of stream carries a stage. A stalled peer stays a timeout and
    /// a refused connection stays an I/O error, so the new label can never
    /// disguise a different fault as a pairing problem.
    #[test]
    fn only_end_of_stream_is_relabelled_with_a_stage() {
        let stage = || LanRuntimeError::EofDuringDeviceAuthentication;

        assert!(matches!(
            LanRuntimeError::Timeout.at_stage(stage()),
            LanRuntimeError::Timeout
        ));
        assert!(matches!(
            LanRuntimeError::MalformedFrame.at_stage(stage()),
            LanRuntimeError::MalformedFrame
        ));
        assert!(matches!(
            LanRuntimeError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                .at_stage(stage()),
            LanRuntimeError::Io(_)
        ));
        assert!(matches!(
            LanRuntimeError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
                .at_stage(stage()),
            LanRuntimeError::EofDuringDeviceAuthentication
        ));
    }

    type BlockingFixtureParts = (
        DesktopLanServer,
        Arc<MobileBackend>,
        DeviceId,
        Arc<StdMutex<Vec<CompanionMessage>>>,
        RuntimeGateController,
        Arc<BlockedBackendState>,
    );

    async fn blocking_fixture(phase: BlockedBackendPhase) -> BlockingFixtureParts {
        let (desktop, mobile, mobile_id, received) = fixture();
        let state = Arc::new(BlockedBackendState::new());
        let desktop = Arc::new(BlockingDesktopBackend {
            inner: desktop,
            phase,
            state: Arc::clone(&state),
        });
        let gate = RuntimeGateController::new(open_gate());
        let server = DesktopLanServer::start(
            LanRuntimeConfig::loopback_for_tests(),
            gate.clone(),
            desktop,
        )
        .await
        .unwrap();
        (server, mobile, mobile_id, received, gate, state)
    }

    fn open_gate() -> RuntimeStartupGate {
        RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: true,
            active_paired_devices: 1,
        }
    }

    fn closed_gate() -> RuntimeStartupGate {
        RuntimeStartupGate {
            connectivity_enabled: false,
            ..open_gate()
        }
    }

    async fn assert_blocked_connect_is_cancelled(
        phase: BlockedBackendPhase,
        signal: CancellationSignal,
    ) {
        let (server, mobile, mobile_id, _, gate, state) = blocking_fixture(phase).await;
        let address = server.local_addr();
        let connect = tokio::spawn(async move {
            MobileLanSession::connect_loopback_for_tests(address, mobile_id, mobile).await
        });
        state.wait_until_entered().await;

        match signal {
            CancellationSignal::Gate => {
                gate.update(closed_gate()).unwrap();
                let result = timeout(Duration::from_secs(1), connect)
                    .await
                    .expect("gate closure did not terminate connect")
                    .expect("connect task panicked");
                assert!(result.is_err());
                timeout(Duration::from_secs(1), server.shutdown())
                    .await
                    .expect("server did not stop after gate closure")
                    .unwrap();
            }
            CancellationSignal::Shutdown => {
                timeout(Duration::from_secs(1), server.shutdown())
                    .await
                    .expect("shutdown did not cancel blocked connect")
                    .unwrap();
                let result = timeout(Duration::from_secs(1), connect)
                    .await
                    .expect("shutdown did not terminate connect")
                    .expect("connect task panicked");
                assert!(result.is_err());
            }
        }

        state.release();
        tokio::task::yield_now().await;
        assert!(!state.completed(), "cancelled backend future resumed");
    }

    async fn assert_blocked_handle_is_cancelled(signal: CancellationSignal) {
        let (server, mobile, mobile_id, received, gate, state) =
            blocking_fixture(BlockedBackendPhase::HandleMessage).await;
        let mut session =
            MobileLanSession::connect_loopback_for_tests(server.local_addr(), mobile_id, mobile)
                .await
                .unwrap();
        let now = unix_now().unwrap();
        let connection = session.connection().clone();
        let ping = CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: "blocked_ping".to_owned(),
            session_id: connection.session_id.clone(),
            sender_device_id: connection.local_device_id.clone(),
            recipient_device_id: connection.remote_device_id.clone(),
            sequence: 1,
            issued_at: now,
            expires_at: connection.expires_at,
            payload: CompanionPayload::Ping,
        };
        session.send(&ping).await.unwrap();
        state.wait_until_entered().await;

        match signal {
            CancellationSignal::Gate => {
                gate.update(closed_gate()).unwrap();
                assert!(
                    timeout(Duration::from_secs(1), session.receive())
                        .await
                        .expect("gate closure did not terminate active session")
                        .is_err()
                );
                timeout(Duration::from_secs(1), server.shutdown())
                    .await
                    .expect("server did not stop after gate closure")
                    .unwrap();
            }
            CancellationSignal::Shutdown => {
                timeout(Duration::from_secs(1), server.shutdown())
                    .await
                    .expect("shutdown did not cancel blocked message")
                    .unwrap();
                assert!(
                    timeout(Duration::from_secs(1), session.receive())
                        .await
                        .expect("shutdown did not terminate active session")
                        .is_err()
                );
            }
        }

        state.release();
        tokio::task::yield_now().await;
        assert!(!state.completed(), "cancelled message action resumed");
        assert!(received.lock().unwrap().is_empty());
    }

    async fn connected_fixture() -> (
        DesktopLanServer,
        MobileLanSession,
        Arc<StdMutex<Vec<CompanionMessage>>>,
        RuntimeGateController,
    ) {
        let (desktop, mobile, mobile_id, received) = fixture();
        let gate = RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: true,
            active_paired_devices: 1,
        };
        let gate = RuntimeGateController::new(gate);
        let server = DesktopLanServer::start(
            LanRuntimeConfig::loopback_for_tests(),
            gate.clone(),
            desktop,
        )
        .await
        .unwrap();
        let session =
            MobileLanSession::connect_loopback_for_tests(server.local_addr(), mobile_id, mobile)
                .await
                .unwrap();
        (server, session, received, gate)
    }

    #[tokio::test]
    async fn blocked_begin_is_cancelled_by_gate_and_shutdown() {
        assert_blocked_connect_is_cancelled(BlockedBackendPhase::Begin, CancellationSignal::Gate)
            .await;
        assert_blocked_connect_is_cancelled(
            BlockedBackendPhase::Begin,
            CancellationSignal::Shutdown,
        )
        .await;
    }

    #[tokio::test]
    async fn blocked_accept_is_cancelled_by_gate_and_shutdown() {
        assert_blocked_connect_is_cancelled(BlockedBackendPhase::Accept, CancellationSignal::Gate)
            .await;
        assert_blocked_connect_is_cancelled(
            BlockedBackendPhase::Accept,
            CancellationSignal::Shutdown,
        )
        .await;
    }

    #[tokio::test]
    async fn blocked_handle_message_is_cancelled_by_gate_and_shutdown() {
        assert_blocked_handle_is_cancelled(CancellationSignal::Gate).await;
        assert_blocked_handle_is_cancelled(CancellationSignal::Shutdown).await;
    }

    #[tokio::test]
    async fn typed_reconnect_and_encrypted_ping_roundtrip() {
        let (server, mut session, received, _gate) = connected_fixture().await;
        let now = unix_now().unwrap();
        let connection = session.connection().clone();
        let ping = CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: "ping_1".to_owned(),
            session_id: connection.session_id.clone(),
            sender_device_id: connection.local_device_id.clone(),
            recipient_device_id: connection.remote_device_id.clone(),
            sequence: 1,
            issued_at: now,
            expires_at: connection.expires_at,
            payload: CompanionPayload::Ping,
        };
        session.send(&ping).await.unwrap();
        let pong = session.receive().await.unwrap();
        assert_eq!(pong.payload, CompanionPayload::Pong);
        assert_eq!(received.lock().unwrap().as_slice(), &[ping]);
        session.disconnect().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn mobile_replay_is_committed_before_message_release() {
        let (server, mut session, _, _gate) = connected_fixture().await;
        let now = unix_now().unwrap();
        let connection = session.connection().clone();
        let ping = CompanionMessage {
            protocol_version: PROTOCOL_VERSION,
            message_id: "ping_replay".to_owned(),
            session_id: connection.session_id.clone(),
            sender_device_id: connection.local_device_id.clone(),
            recipient_device_id: connection.remote_device_id.clone(),
            sequence: 1,
            issued_at: now,
            expires_at: connection.expires_at,
            payload: CompanionPayload::Ping,
        };
        session.send(&ping).await.unwrap();
        let packet = read_packet(&mut session.stream, Duration::from_secs(1))
            .await
            .unwrap();
        let frame = decode_encrypted_frame(&packet.body).unwrap();
        let now = unix_now().unwrap();
        let (message, replay) = session.authenticated.cipher.decrypt(&frame, now).unwrap();
        let accepted = session
            .backend
            .accept_message(&connection, message.clone(), replay.clone(), now)
            .await
            .unwrap();
        assert_eq!(accepted, message);
        assert!(
            session
                .backend
                .accept_message(&connection, message, replay, now)
                .await
                .is_err()
        );
        session.disconnect().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn plaintext_after_auth_is_closed_as_downgrade() {
        let (server, mut session, received, _gate) = connected_fixture().await;
        write_packet(
            &mut session.stream,
            PacketKind::ClientHello,
            b"mobile_again",
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let result = read_packet(&mut session.stream, Duration::from_secs(1)).await;
        assert!(result.is_err());
        assert!(received.lock().unwrap().is_empty());
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn startup_and_public_endpoint_fail_closed() {
        let (desktop, mobile, mobile_id, _) = fixture();
        let closed = RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: false,
            active_paired_devices: 1,
        };
        assert!(matches!(
            DesktopLanServer::start(
                LanRuntimeConfig::loopback_for_tests(),
                RuntimeGateController::new(closed),
                desktop,
            )
            .await,
            Err(LanRuntimeError::StartupGateClosed)
        ));
        assert!(matches!(
            MobileLanSession::connect("8.8.8.8:42492".parse().unwrap(), mobile_id, mobile).await,
            Err(LanRuntimeError::NonPrivateAddress)
        ));
    }

    #[tokio::test]
    async fn closing_dynamic_gate_terminates_active_session() {
        let (server, mut session, _, gate) = connected_fixture().await;
        gate.update(RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: false,
            active_paired_devices: 1,
        })
        .unwrap();
        assert!(session.receive().await.is_err());
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn idle_connection_and_shutdown_are_bounded() {
        let (server, mut session, _, _gate) = connected_fixture().await;
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(session.receive().await.is_err());
        server.shutdown().await.unwrap();
    }
}

/// Reconnect of an already paired phone whose desktop record is active.
///
/// The fixtures in the module above give the desktop a monotonically increasing
/// `challenge_sequence` (`AtomicU64::fetch_add`), so nothing there could ever
/// catch what production did: the Agent Wallet manager drew an independent
/// `random_nonzero_u64()` per handshake, while the phone keeps a durable,
/// strictly monotonic high-water mark for the `companion_session_challenge`
/// scope. These tests reproduce the real pairing on the real hardware, where the
/// phone's persisted mark was already 15556705341435925004, and hold the desktop
/// to the shared production source
/// (`hpay_companion_protocol::DesktopChallengeSequence`) that the manager now
/// uses at crates/agent-wallet-core/src/service/companion/session.rs.
#[cfg(test)]
mod reconnect_challenge_sequence_tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;

    use hpay_companion_protocol::{
        CompanionConnection, CompanionError, CompanionMessage, DesktopChallengeSequence,
        DesktopSessionAttempt, DeviceId, DeviceRegistry, DeviceRole, EstablishedSession,
        ReplayGuard, ReplayGuardSnapshot, ReplayMetadata, SessionChallenge, SessionConfirmation,
        SessionResponse, SoftwareDeviceIdentity,
    };
    use tokio::sync::Mutex;

    use super::MobileLanSession;
    use crate::backend::{
        DesktopHandshake, DesktopSessionBackend, HandleMessageResult, MobileHandshake,
        MobileSessionBackend, RuntimeFuture,
    };
    use crate::config::{LanRuntimeConfig, RuntimeGateController, RuntimeStartupGate};
    use crate::error::LanRuntimeError;
    use crate::server::DesktopLanServer;

    /// Sequence observed in the live phone's durable state for the
    /// `companion_session_challenge` scope after the last accepted handshake.
    const OBSERVED_HIGH_WATER_SEQUENCE: u64 = 15_556_705_341_435_925_004;

    /// Desktop half wired exactly like production: the challenge sequence comes
    /// from the shared strictly increasing source, seeded so that the first
    /// handshake lands on the sequence the live phone actually recorded.
    struct ProductionSequenceDesktopBackend {
        signer: Arc<SoftwareDeviceIdentity>,
        registry: DeviceRegistry,
        replay: Arc<Mutex<ReplayGuard>>,
        sequences: StdMutex<DesktopChallengeSequence>,
        /// Every sequence handed out, in order, so a test can assert the
        /// contract the phone verifies rather than only its consequences.
        issued: StdMutex<Vec<u64>>,
    }

    struct DesktopAttempt {
        inner: DesktopSessionAttempt,
        signer: Arc<SoftwareDeviceIdentity>,
        registry: DeviceRegistry,
        replay: Arc<Mutex<ReplayGuard>>,
    }

    impl DesktopHandshake for DesktopAttempt {
        fn challenge(&self) -> &SessionChallenge {
            self.inner.challenge()
        }

        fn accept(
            self: Box<Self>,
            response: SessionResponse,
            now: u64,
        ) -> RuntimeFuture<'static, (SessionConfirmation, EstablishedSession)> {
            Box::pin(async move {
                let mut inner = self.inner;
                let mut replay = self.replay.lock().await;
                Ok(inner
                    .accept_response(
                        &response,
                        self.signer.as_ref(),
                        &self.registry,
                        &mut replay,
                        now,
                    )
                    .await?)
            })
        }
    }

    impl DesktopSessionBackend for ProductionSequenceDesktopBackend {
        fn begin<'a>(
            &'a self,
            mobile_device_id: DeviceId,
            now: u64,
        ) -> RuntimeFuture<'a, Box<dyn DesktopHandshake>> {
            Box::pin(async move {
                let sequence = self
                    .sequences
                    .lock()
                    .expect("challenge sequence source")
                    .next(0, now)?;
                self.issued.lock().expect("issued list").push(sequence);
                let inner = DesktopSessionAttempt::start(
                    self.signer.as_ref(),
                    &self.registry,
                    "wallet_one",
                    mobile_device_id,
                    sequence,
                    now,
                    // Same constant the production desktop backend requests
                    // (crates/wallet-tauri-common/src/companion_backend.rs).
                    hpay_companion_protocol::MAX_REQUESTED_SESSION_LIFETIME_SECS,
                )
                .await?;
                Ok(Box::new(DesktopAttempt {
                    inner,
                    signer: Arc::clone(&self.signer),
                    registry: self.registry.clone(),
                    replay: Arc::clone(&self.replay),
                }) as Box<dyn DesktopHandshake>)
            })
        }

        fn handle_message<'a>(
            &'a self,
            _connection: &'a CompanionConnection,
            _message: CompanionMessage,
            _replay: ReplayMetadata,
            _now: u64,
        ) -> RuntimeFuture<'a, HandleMessageResult> {
            Box::pin(async move { Ok(HandleMessageResult { response: None }) })
        }
    }

    /// Phone half wired exactly like `AndroidMobileBackend`: the replay guard is
    /// rebuilt from durable state on every handshake, the response sequence is a
    /// persisted counter, and each refusal is named through
    /// `LanRuntimeError::from_challenge_refusal`
    /// (apps/mobile/src-tauri/src/agent_companion/session.rs).
    struct DurableMobileBackend {
        signer: Arc<SoftwareDeviceIdentity>,
        registry: DeviceRegistry,
        durable: Mutex<(ReplayGuardSnapshot, u64)>,
        /// Seconds this phone's clock reads behind the desktop's.
        ///
        /// The runtime takes every timestamp from `SystemTime::now()`, so a test
        /// that leaves this at zero puts both devices on one clock - which is
        /// exactly why the tests in this module could not catch the live
        /// reconnect failure, where the desktop was one second ahead.
        clock_behind_secs: u64,
    }

    impl DurableMobileBackend {
        fn phone_now(&self, now: u64) -> u64 {
            now - self.clock_behind_secs
        }
    }

    struct MobileAttempt {
        inner: hpay_companion_protocol::MobileSessionAttempt,
        registry: DeviceRegistry,
        clock_behind_secs: u64,
    }

    impl MobileHandshake for MobileAttempt {
        fn response(&self) -> &SessionResponse {
            self.inner.response()
        }

        fn verify(
            self: Box<Self>,
            confirmation: SessionConfirmation,
            now: u64,
        ) -> RuntimeFuture<'static, EstablishedSession> {
            Box::pin(async move {
                let now = now - self.clock_behind_secs;
                self.inner
                    .verify_confirmation(&confirmation, &self.registry, now)
                    .map_err(LanRuntimeError::from_challenge_refusal)
            })
        }
    }

    impl MobileSessionBackend for DurableMobileBackend {
        fn respond<'a>(
            &'a self,
            challenge: SessionChallenge,
            now: u64,
        ) -> RuntimeFuture<'a, Box<dyn MobileHandshake>> {
            Box::pin(async move {
                let now = self.phone_now(now);
                let mut durable = self.durable.lock().await;
                let (snapshot, response_sequence) = durable.clone();
                let mut replay = ReplayGuard::from_snapshot(snapshot, now)
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                let response_sequence = response_sequence
                    .checked_add(1)
                    .ok_or(LanRuntimeError::CompanionStateUnavailable)?;
                let inner = hpay_companion_protocol::MobileSessionAttempt::respond(
                    challenge,
                    self.signer.as_ref(),
                    &self.registry,
                    &mut replay,
                    response_sequence,
                    now,
                )
                .await
                .map_err(LanRuntimeError::from_challenge_refusal)?;
                *durable = (
                    replay
                        .snapshot(now)
                        .map_err(|_| LanRuntimeError::CompanionStatePersistFailed)?,
                    response_sequence,
                );
                Ok(Box::new(MobileAttempt {
                    inner,
                    registry: self.registry.clone(),
                    clock_behind_secs: self.clock_behind_secs,
                }) as Box<dyn MobileHandshake>)
            })
        }

        fn accept_message<'a>(
            &'a self,
            _connection: &'a CompanionConnection,
            message: CompanionMessage,
            replay: ReplayMetadata,
            now: u64,
        ) -> RuntimeFuture<'a, CompanionMessage> {
            Box::pin(async move {
                let now = self.phone_now(now);
                let mut durable = self.durable.lock().await;
                let (snapshot, response_sequence) = durable.clone();
                let mut guard = ReplayGuard::from_snapshot(snapshot, now)
                    .map_err(|_| LanRuntimeError::CompanionStateUnavailable)?;
                let permit = guard
                    .check(&replay, now)
                    .map_err(LanRuntimeError::from_challenge_refusal)?;
                guard
                    .commit(permit, now)
                    .map_err(LanRuntimeError::from_challenge_refusal)?;
                *durable = (
                    guard
                        .snapshot(now)
                        .map_err(|_| LanRuntimeError::CompanionStatePersistFailed)?,
                    response_sequence,
                );
                Ok(message)
            })
        }
    }

    fn open_gate() -> RuntimeStartupGate {
        RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: true,
            active_paired_devices: 1,
        }
    }

    type PairedDevices = (
        DesktopLanServer,
        Arc<ProductionSequenceDesktopBackend>,
        Arc<DurableMobileBackend>,
        DeviceId,
        RuntimeGateController,
    );

    /// A phone that is already paired, with both device records active, and a
    /// desktop whose counter is one below the mark the live phone recorded, so
    /// the first handshake reproduces that mark exactly. Both devices read one
    /// clock.
    async fn paired_devices() -> PairedDevices {
        paired_devices_with_phone_clock_behind(0).await
    }

    /// The same pair, with the phone's clock `clock_behind_secs` behind the
    /// desktop's. On the live hardware the offset was one second, and every
    /// timestamp in the handshake is stamped by whichever device produced it.
    async fn paired_devices_with_phone_clock_behind(clock_behind_secs: u64) -> PairedDevices {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let desktop = Arc::new(SoftwareDeviceIdentity::generate(DeviceRole::Desktop));
        let mobile = Arc::new(SoftwareDeviceIdentity::generate(DeviceRole::Mobile));
        let mut registry = DeviceRegistry::new();
        // Both records are active: nothing here is revoked, and the desktop
        // record is exactly the "Read only, active" record the desktop shows.
        registry
            .register(
                desktop
                    .public_record("wallet_one", BTreeSet::new(), now - 60)
                    .unwrap(),
            )
            .unwrap();
        registry
            .register(
                mobile
                    .public_record(
                        "wallet_one",
                        BTreeSet::from([
                            hpay_companion_protocol::DevicePermission::ViewAgentWalletStatus,
                        ]),
                        now - 60,
                    )
                    .unwrap(),
            )
            .unwrap();
        let mobile_id = mobile.device_id().clone();
        let desktop_backend = Arc::new(ProductionSequenceDesktopBackend {
            signer: desktop,
            registry: registry.clone(),
            replay: Arc::new(Mutex::new(ReplayGuard::new())),
            sequences: StdMutex::new(DesktopChallengeSequence::resuming_from(
                OBSERVED_HIGH_WATER_SEQUENCE - 1,
            )),
            issued: StdMutex::new(Vec::new()),
        });
        let mobile_backend = Arc::new(DurableMobileBackend {
            signer: mobile,
            registry,
            durable: Mutex::new((
                ReplayGuard::new()
                    .snapshot(now - clock_behind_secs)
                    .unwrap(),
                0,
            )),
            clock_behind_secs,
        });
        let gate = RuntimeGateController::new(open_gate());
        let server = DesktopLanServer::start(
            LanRuntimeConfig::loopback_for_tests(),
            gate.clone(),
            Arc::clone(&desktop_backend) as Arc<dyn DesktopSessionBackend>,
        )
        .await
        .unwrap();
        (server, desktop_backend, mobile_backend, mobile_id, gate)
    }

    /// A phone that is paired, whose desktop record is active, and whose pending
    /// pairing flag is already cleared must be able to reconnect, over and over,
    /// against its own durable replay guard. With an independently drawn
    /// challenge sequence it could not: the first handshake left the mark at
    /// 15556705341435925004 and 84.3% of later draws landed below it, so the
    /// phone refused its own paired desktop before any wallet state was touched.
    #[tokio::test]
    async fn paired_phone_can_reconnect_after_a_high_challenge_sequence() {
        let (server, desktop, mobile, mobile_id, _gate) = paired_devices().await;
        let address = server.local_addr();

        for attempt in 0..4 {
            let session = MobileLanSession::connect_loopback_for_tests(
                address,
                mobile_id.clone(),
                Arc::clone(&mobile) as Arc<dyn MobileSessionBackend>,
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "reconnect {attempt} of a paired phone with an active desktop record must \
                     succeed, got: {error}"
                )
            });
            drop(session);
        }

        // The contract the phone actually verifies, asserted directly.
        let issued = desktop.issued.lock().expect("issued list").clone();
        assert_eq!(issued.len(), 4);
        assert_eq!(
            issued[0], OBSERVED_HIGH_WATER_SEQUENCE,
            "the first handshake must reproduce the mark the live phone recorded",
        );
        for pair in issued.windows(2) {
            assert!(
                pair[1] > pair[0],
                "challenge sequence {} did not exceed {}",
                pair[1],
                pair[0],
            );
        }
        server.shutdown().await.unwrap();
    }

    /// The replay guard is not relaxed, and the refusal now says what it is.
    ///
    /// A desktop that really does reoffer a consumed challenge sequence - a
    /// rolled-back or rogue one - is still refused. What changed is only the
    /// error that reaches the owner: it names the cause, says the pairing is
    /// fine, gives the remedy and the five-minute bound, and is no longer the
    /// catch-all "companion backend rejected the operation".
    #[tokio::test]
    async fn a_reissued_challenge_sequence_is_refused_and_names_its_reason() {
        let (server, desktop, mobile, mobile_id, _gate) = paired_devices().await;
        let address = server.local_addr();
        let first = MobileLanSession::connect_loopback_for_tests(
            address,
            mobile_id.clone(),
            Arc::clone(&mobile) as Arc<dyn MobileSessionBackend>,
        )
        .await
        .expect("the first authenticated session must establish");
        drop(first);

        // Rewind the desktop's counter so the next handshake reoffers the exact
        // sequence the phone has already consumed.
        *desktop.sequences.lock().expect("challenge sequence source") =
            DesktopChallengeSequence::resuming_from(OBSERVED_HIGH_WATER_SEQUENCE - 1);

        let error = MobileLanSession::connect_loopback_for_tests(
            address,
            mobile_id,
            mobile as Arc<dyn MobileSessionBackend>,
        )
        .await
        .expect_err("a consumed challenge sequence must stay refused");
        assert!(
            matches!(error, LanRuntimeError::StaleDesktopChallengeSequence),
            "expected the named stale-sequence refusal, got {error:?}"
        );
        let message = error.to_string();
        assert_ne!(message, "companion backend rejected the operation");
        assert!(
            message.contains("already accepted a newer session challenge"),
            "{message}"
        );
        assert!(message.contains("nothing needs to be reset"), "{message}");
        // It must tell the owner to try again, and it must not do so by naming a
        // control the phone does not have. Both of these labels were renamed on
        // the phone (apps/mobile/src/agent/companionStatus.ts), so a Rust string
        // naming either is an instruction the owner cannot follow. Pinning the
        // absence rather than a current label is what keeps this from going
        // stale the next time the phone renames a button.
        assert!(
            message.to_lowercase().contains("try connecting again"),
            "{message}"
        );
        assert!(!message.contains("Connect and sync"), "{message}");
        assert!(!message.contains("Reset mobile companion"), "{message}");
        assert!(message.contains("five minutes"), "{message}");
        assert!(error.is_retryable_by_the_owner());
        server.shutdown().await.unwrap();
    }

    /// Every refusal on this path carries its own reason. A permanent one must
    /// read as permanent and a transient one as transient, or the owner cannot
    /// tell "press it again" from "pair again".
    #[test]
    fn each_challenge_refusal_is_named_and_classified() {
        let cases = [
            (
                CompanionError::SequenceReplay,
                LanRuntimeError::StaleDesktopChallengeSequence,
                true,
            ),
            (
                CompanionError::NonceReplay,
                LanRuntimeError::ReusedDesktopChallengeNonce,
                true,
            ),
            (
                CompanionError::Expired,
                LanRuntimeError::DesktopChallengeExpired,
                true,
            ),
            // Its own error now, not a second door into the expiry one. It is
            // not retryable on its own: the same two clocks would be compared
            // again and refuse again.
            (
                CompanionError::InvalidIssuedAt,
                LanRuntimeError::DesktopChallengeClockOffsetTooLarge,
                false,
            ),
            (
                CompanionError::DeviceRevoked,
                LanRuntimeError::DeviceNoLongerAuthorized,
                false,
            ),
            (
                CompanionError::UnknownDevice,
                LanRuntimeError::DeviceNoLongerAuthorized,
                false,
            ),
            (
                CompanionError::InvalidSignature,
                LanRuntimeError::DesktopChallengeSignatureRejected,
                false,
            ),
        ];
        for (cause, expected, retryable) in cases {
            let named = LanRuntimeError::from_challenge_refusal(cause.clone());
            assert_eq!(
                std::mem::discriminant(&named),
                std::mem::discriminant(&expected),
                "{cause:?} was not named",
            );
            assert_ne!(
                named.to_string(),
                "companion backend rejected the operation"
            );
            assert_eq!(named.is_retryable_by_the_owner(), retryable, "{cause:?}");
        }
        // Anything without a specific meaning still keeps the protocol reason
        // rather than collapsing to the catch-all.
        let fallback = LanRuntimeError::from_challenge_refusal(CompanionError::MalformedMessage);
        assert!(matches!(fallback, LanRuntimeError::Protocol(_)));
        assert!(
            fallback
                .to_string()
                .contains("companion message is malformed")
        );
        assert!(!fallback.is_retryable_by_the_owner());
    }

    /// The live failure, at the runtime layer, with the two devices on the two
    /// clocks that were actually measured.
    ///
    /// Every test above this one puts both halves on `SystemTime::now()`, which
    /// is why they all passed while the owner's phone could not connect. Here
    /// the phone reads one second behind, exactly as measured, and the
    /// authenticated session must still establish.
    ///
    /// The frames that follow cross the same two clocks; that half is covered
    /// where it lives, in `CompanionMessage::validate_at`
    /// (crates/companion-protocol/src/message.rs).
    #[tokio::test]
    async fn a_phone_whose_clock_is_one_second_behind_still_reconnects() {
        let (server, desktop, mobile, mobile_id, _gate) =
            paired_devices_with_phone_clock_behind(1).await;
        let address = server.local_addr();

        for attempt in 0..3 {
            let session = MobileLanSession::connect_loopback_for_tests(
                address,
                mobile_id.clone(),
                Arc::clone(&mobile) as Arc<dyn MobileSessionBackend>,
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "reconnect {attempt} with the phone one second behind its desktop must \
                     succeed, got: {error}"
                )
            });
            drop(session);
        }

        // The sequence contract from the previous pass is still held.
        let issued = desktop.issued.lock().expect("issued list").clone();
        assert_eq!(issued.len(), 3);
        for pair in issued.windows(2) {
            assert!(pair[1] > pair[0], "{} did not exceed {}", pair[1], pair[0]);
        }
        server.shutdown().await.unwrap();
    }

    /// A clock offset the protocol does not tolerate is still refused, and the
    /// refusal now says what it actually is.
    #[test]
    fn a_clock_offset_and_an_expiry_are_two_different_sentences() {
        let expired = LanRuntimeError::from_challenge_refusal(CompanionError::Expired);
        let skewed = LanRuntimeError::from_challenge_refusal(CompanionError::InvalidIssuedAt);
        assert!(matches!(expired, LanRuntimeError::DesktopChallengeExpired));
        assert!(matches!(
            skewed,
            LanRuntimeError::DesktopChallengeClockOffsetTooLarge
        ));

        let expired = expired.to_string();
        let skewed = skewed.to_string();
        assert_ne!(expired, skewed);
        // Neither may still be the old single sentence that named a clock cause
        // for both, and sent a real investigation to two correct clocks.
        for message in [&expired, &skewed] {
            assert!(
                !message.contains("expired or dated in the future"),
                "{message}"
            );
        }
        // The expiry sentence must not send anyone to their clock settings, and
        // the action it does name is one that resolves it: a new connect draws
        // a new challenge.
        assert!(
            !expired.to_lowercase().contains("date and time"),
            "{expired}"
        );
        assert!(expired.to_lowercase().contains("expired"), "{expired}");
        assert!(
            expired.to_lowercase().contains("try connecting again"),
            "{expired}"
        );
        // The clock sentence must name the clock, and must not claim the
        // challenge expired when it had not.
        assert!(skewed.to_lowercase().contains("date and time"), "{skewed}");
        assert!(!skewed.to_lowercase().contains("expired"), "{skewed}");
        // Neither may tell the owner to re-pair or reset over this.
        for message in [&expired, &skewed] {
            assert!(
                !message.to_lowercase().contains("pair this phone again"),
                "{message}"
            );
            assert!(
                message.contains("Nothing about the pairing is wrong"),
                "{message}"
            );
        }
    }
}
