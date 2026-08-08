use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hpay_companion_protocol::{EncryptedCompanionFrame, PairingConfirmation, PairingRequest};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::backend::RuntimeFuture;
use crate::config::{LanRuntimeConfig, validate_peer_ip, validate_remote_endpoint};
use crate::error::{LanRuntimeError, LanRuntimeResult};
use crate::framing::{PacketKind, read_packet, write_packet};
use crate::limits::AdmissionControl;
use crate::wire::{
    decode_encrypted_frame, decode_pairing_confirmation, decode_pairing_request,
    encode_encrypted_frame, encode_pairing_confirmation, encode_pairing_request,
};

pub trait DesktopPairingBackend: Send + Sync {
    fn accept_request<'a>(
        &'a self,
        request: PairingRequest,
    ) -> RuntimeFuture<'a, PairingConfirmation>;

    fn accept_ack<'a>(&'a self, ack: EncryptedCompanionFrame) -> RuntimeFuture<'a, ()>;
}

pub struct PairingLanServer {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<LanRuntimeResult<()>>>,
    shutdown_timeout: Duration,
}

impl PairingLanServer {
    pub async fn start(
        config: LanRuntimeConfig,
        backend: Arc<dyn DesktopPairingBackend>,
    ) -> LanRuntimeResult<Self> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind_addr()).await?;
        let local_addr = listener.local_addr()?;
        let (shutdown, receiver) = watch::channel(false);
        let shutdown_timeout = config.shutdown_timeout();
        let task = tokio::spawn(run_pairing_listener(listener, config, backend, receiver));
        Ok(Self {
            local_addr,
            shutdown,
            task: Some(task),
            shutdown_timeout,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn is_running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    pub async fn shutdown(mut self) -> LanRuntimeResult<()> {
        let _ = self.shutdown.send(true);
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(self.shutdown_timeout, &mut task).await {
            Ok(result) => result.map_err(|_| LanRuntimeError::Task)??,
            Err(_) => {
                task.abort();
                let _ = task.await;
                return Err(LanRuntimeError::Timeout);
            }
        }
        Ok(())
    }
}

impl Drop for PairingLanServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub struct MobilePairingTransport;

impl MobilePairingTransport {
    pub async fn submit_request(
        endpoint: SocketAddr,
        request: &PairingRequest,
    ) -> LanRuntimeResult<PairingConfirmation> {
        submit_request_with_policy(endpoint, request, false).await
    }

    pub async fn submit_ack(
        endpoint: SocketAddr,
        ack: &EncryptedCompanionFrame,
    ) -> LanRuntimeResult<()> {
        submit_ack_with_policy(endpoint, ack, false).await
    }
}

async fn submit_request_with_policy(
    endpoint: SocketAddr,
    request: &PairingRequest,
    allow_test_loopback: bool,
) -> LanRuntimeResult<PairingConfirmation> {
    validate_remote_endpoint(endpoint, allow_test_loopback)?;
    let mut stream = connect(endpoint).await?;
    let body = encode_pairing_request(request)?;
    write_packet(
        &mut stream,
        PacketKind::PairingRequest,
        &body,
        Duration::from_secs(10),
    )
    .await?;
    let response = read_packet(&mut stream, Duration::from_secs(15)).await?;
    if response.kind != PacketKind::PairingConfirmation {
        return Err(LanRuntimeError::MalformedFrame);
    }
    decode_pairing_confirmation(&response.body)
}

async fn submit_ack_with_policy(
    endpoint: SocketAddr,
    ack: &EncryptedCompanionFrame,
    allow_test_loopback: bool,
) -> LanRuntimeResult<()> {
    validate_remote_endpoint(endpoint, allow_test_loopback)?;
    let mut stream = connect(endpoint).await?;
    let body = encode_encrypted_frame(ack)?;
    write_packet(
        &mut stream,
        PacketKind::PairingAck,
        &body,
        Duration::from_secs(10),
    )
    .await?;
    let response = read_packet(&mut stream, Duration::from_secs(15)).await?;
    if response.kind != PacketKind::PairingReceived || !response.body.is_empty() {
        return Err(LanRuntimeError::MalformedFrame);
    }
    Ok(())
}
async fn connect(endpoint: SocketAddr) -> LanRuntimeResult<TcpStream> {
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(endpoint))
        .await
        .map_err(|_| LanRuntimeError::Timeout)??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn run_pairing_listener(
    listener: TcpListener,
    config: LanRuntimeConfig,
    backend: Arc<dyn DesktopPairingBackend>,
    mut shutdown: watch::Receiver<bool>,
) -> LanRuntimeResult<()> {
    let global = Arc::new(Semaphore::new(config.max_connections()));
    let admission = Arc::new(AdmissionControl::new(
        config.max_connections_per_peer(),
        config.max_attempts_per_minute(),
        config.max_global_attempts_per_minute(),
    ));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                if validate_peer_ip(peer.ip(), config.allow_test_loopback()).is_err() {
                    drop(stream);
                    continue;
                }
                let Ok(global_permit) = Arc::clone(&global).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let Ok(peer_permit) = admission.admit(peer.ip(), Instant::now()) else {
                    drop(stream);
                    continue;
                };
                let backend = Arc::clone(&backend);
                let connection_config = config.clone();
                connections.spawn(async move {
                    let _global_permit = global_permit;
                    let _peer_permit = peer_permit;
                    handle_pairing_connection(stream, backend, connection_config).await
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(_)) = result {
                    // One failed peer remains isolated from the listener.
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_pairing_connection(
    mut stream: TcpStream,
    backend: Arc<dyn DesktopPairingBackend>,
    config: LanRuntimeConfig,
) -> LanRuntimeResult<()> {
    stream.set_nodelay(true)?;
    let packet = read_packet(&mut stream, config.handshake_timeout()).await?;
    match packet.kind {
        PacketKind::PairingRequest => {
            let request = decode_pairing_request(&packet.body)?;
            let confirmation = backend.accept_request(request).await?;
            let body = encode_pairing_confirmation(&confirmation)?;
            write_packet(
                &mut stream,
                PacketKind::PairingConfirmation,
                &body,
                config.io_timeout(),
            )
            .await
        }
        PacketKind::PairingAck => {
            let ack = decode_encrypted_frame(&packet.body)?;
            backend.accept_ack(ack).await?;
            write_packet(
                &mut stream,
                PacketKind::PairingReceived,
                &[],
                config.io_timeout(),
            )
            .await
        }
        _ => Err(LanRuntimeError::MalformedFrame),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use hpay_companion_protocol::{DeviceId, FRAME_VERSION};

    use super::*;

    struct RecordingBackend {
        confirmation: PairingConfirmation,
        requests: StdMutex<Vec<PairingRequest>>,
        acknowledgements: StdMutex<Vec<EncryptedCompanionFrame>>,
    }

    impl DesktopPairingBackend for RecordingBackend {
        fn accept_request<'a>(
            &'a self,
            request: PairingRequest,
        ) -> RuntimeFuture<'a, PairingConfirmation> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request);
                Ok(self.confirmation.clone())
            })
        }

        fn accept_ack<'a>(&'a self, ack: EncryptedCompanionFrame) -> RuntimeFuture<'a, ()> {
            Box::pin(async move {
                self.acknowledgements.lock().unwrap().push(ack);
                Ok(())
            })
        }
    }

    fn request() -> PairingRequest {
        PairingRequest {
            protocol_version: 1,
            pairing_id: "pairing_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
            mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
            mobile_ephemeral_public_key: "11".repeat(32),
            mobile_identity_public_key: format!("04{}", "22".repeat(64)),
            mobile_identity_fingerprint: "33".repeat(32),
            pairing_nonce: "44".repeat(32),
            mobile_challenge: "55".repeat(32),
            issued_at: 100,
            expires_at: 200,
            identity_signature: "66".repeat(64),
        }
    }

    fn confirmation() -> PairingConfirmation {
        PairingConfirmation {
            protocol_version: 1,
            pairing_id: "pairing_one".to_owned(),
            agent_wallet_id: "wallet_one".to_owned(),
            desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
            mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
            desktop_challenge: "77".repeat(32),
            verification_code: "123456".to_owned(),
            session_id: "session_one".to_owned(),
            issued_at: 101,
            expires_at: 200,
            desktop_identity_signature: "88".repeat(64),
        }
    }

    fn acknowledgement() -> EncryptedCompanionFrame {
        EncryptedCompanionFrame {
            frame_version: FRAME_VERSION,
            session_id: "session_one".to_owned(),
            sender_device_id: DeviceId::parse("mobile_one").unwrap(),
            recipient_device_id: DeviceId::parse("desktop_one").unwrap(),
            sequence: 1,
            issued_at: 102,
            expires_at: 200,
            nonce_hex: "99".repeat(12),
            ciphertext_hex: "aa".repeat(32),
        }
    }

    #[tokio::test]
    async fn pairing_request_and_ack_roundtrip_over_bounded_listener() {
        let expected_confirmation = confirmation();
        let backend = Arc::new(RecordingBackend {
            confirmation: expected_confirmation.clone(),
            requests: StdMutex::new(Vec::new()),
            acknowledgements: StdMutex::new(Vec::new()),
        });
        let server =
            PairingLanServer::start(LanRuntimeConfig::loopback_for_tests(), backend.clone())
                .await
                .unwrap();
        let address = server.local_addr();
        let request = request();
        let ack = acknowledgement();

        let received = submit_request_with_policy(address, &request, true)
            .await
            .unwrap();
        assert_eq!(received, expected_confirmation);
        submit_ack_with_policy(address, &ack, true).await.unwrap();

        assert_eq!(backend.requests.lock().unwrap().as_slice(), &[request]);
        assert_eq!(backend.acknowledgements.lock().unwrap().as_slice(), &[ack]);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn production_mobile_transport_rejects_loopback_before_connecting() {
        let address: SocketAddr = "127.0.0.1:42492".parse().unwrap();
        assert!(matches!(
            MobilePairingTransport::submit_request(address, &request()).await,
            Err(LanRuntimeError::NonPrivateAddress)
        ));
        assert!(matches!(
            MobilePairingTransport::submit_ack(address, &acknowledgement()).await,
            Err(LanRuntimeError::NonPrivateAddress)
        ));
    }
}
