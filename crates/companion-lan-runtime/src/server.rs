use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hpay_companion_protocol::SessionResponse;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::backend::{AuthenticatedSession, DesktopSessionBackend};
use crate::config::{
    LanRuntimeConfig, RuntimeGateController, RuntimeStartupGate, validate_peer_ip,
};
use crate::error::{LanRuntimeError, LanRuntimeResult};
use crate::framing::{Packet, PacketKind, read_packet, write_packet};
use crate::limits::AdmissionControl;
use crate::wire::{decode_client_hello, decode_encrypted_frame, encode_encrypted_frame};

pub struct DesktopLanServer {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<LanRuntimeResult<()>>>,
    shutdown_timeout: std::time::Duration,
}

impl std::fmt::Debug for DesktopLanServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesktopLanServer")
            .field("local_addr", &self.local_addr)
            .field("task", &"<owned>")
            .finish()
    }
}

impl DesktopLanServer {
    pub async fn start(
        config: LanRuntimeConfig,
        gate: RuntimeGateController,
        backend: Arc<dyn DesktopSessionBackend>,
    ) -> LanRuntimeResult<Self> {
        gate.current().validate()?;
        config.validate()?;
        let listener = TcpListener::bind(config.bind_addr()).await?;
        let local_addr = listener.local_addr()?;
        let (shutdown, receiver) = watch::channel(false);
        let shutdown_timeout = config.shutdown_timeout();
        let runtime_gate = gate.subscribe();
        let task = tokio::spawn(run_listener(
            listener,
            config,
            backend,
            runtime_gate,
            receiver,
        ));
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
            Ok(result) => result.map_err(|_| LanRuntimeError::Task)?,
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(LanRuntimeError::Timeout)
            }
        }
    }
}

impl Drop for DesktopLanServer {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_listener(
    listener: TcpListener,
    config: LanRuntimeConfig,
    backend: Arc<dyn DesktopSessionBackend>,
    mut runtime_gate: watch::Receiver<RuntimeStartupGate>,
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
            changed = runtime_gate.changed() => {
                if changed.is_err() || runtime_gate.borrow().validate().is_err() { break; }
            }
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
                let connection_gate = runtime_gate.clone();
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    let _global_permit = global_permit;
                    let _peer_permit = peer_permit;
                    handle_connection(
                        stream,
                        backend,
                        connection_config,
                        connection_gate,
                        connection_shutdown,
                    )
                    .await
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(_join_error)) = result {
                    // One failed peer is isolated. JoinSet retains every task.
                }
            }
        }
    }

    let graceful = async { while connections.join_next().await.is_some() {} };
    if timeout(config.shutdown_timeout(), graceful).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    backend: Arc<dyn DesktopSessionBackend>,
    config: LanRuntimeConfig,
    mut runtime_gate: watch::Receiver<RuntimeStartupGate>,
    mut shutdown: watch::Receiver<bool>,
) -> LanRuntimeResult<()> {
    stream.set_nodelay(true)?;
    runtime_gate.borrow().validate()?;
    let hello = read_with_controls(
        &mut stream,
        config.handshake_timeout(),
        &mut runtime_gate,
        &mut shutdown,
    )
    .await?;
    if hello.kind != PacketKind::ClientHello {
        return Err(LanRuntimeError::MalformedFrame);
    }
    let mobile_device_id = decode_client_hello(&hello.body)?;
    let now = unix_now()?;
    let attempt = await_with_controls(
        backend.begin(mobile_device_id, now),
        &mut runtime_gate,
        &mut shutdown,
    )
    .await?;
    let challenge = attempt.challenge().to_bytes()?;
    await_with_controls(
        write_packet(
            &mut stream,
            PacketKind::SessionChallenge,
            &challenge,
            config.io_timeout(),
        ),
        &mut runtime_gate,
        &mut shutdown,
    )
    .await?;

    let response = read_with_controls(
        &mut stream,
        config.human_response_timeout(),
        &mut runtime_gate,
        &mut shutdown,
    )
    .await?;
    if response.kind != PacketKind::SessionResponse {
        return Err(LanRuntimeError::MalformedFrame);
    }
    let response = SessionResponse::from_bytes(&response.body)?;
    let now = unix_now()?;
    let (confirmation, established) = await_with_controls(
        attempt.accept(response, now),
        &mut runtime_gate,
        &mut shutdown,
    )
    .await?;
    let confirmation = confirmation.to_bytes()?;
    await_with_controls(
        write_packet(
            &mut stream,
            PacketKind::SessionConfirmation,
            &confirmation,
            config.io_timeout(),
        ),
        &mut runtime_gate,
        &mut shutdown,
    )
    .await?;
    let session = AuthenticatedSession::from_desktop(established, now)?;
    run_encrypted_desktop_session(
        &mut stream,
        session,
        backend,
        config,
        &mut runtime_gate,
        &mut shutdown,
    )
    .await
}

async fn run_encrypted_desktop_session(
    stream: &mut TcpStream,
    session: AuthenticatedSession,
    backend: Arc<dyn DesktopSessionBackend>,
    config: LanRuntimeConfig,
    runtime_gate: &mut watch::Receiver<RuntimeStartupGate>,
    shutdown: &mut watch::Receiver<bool>,
) -> LanRuntimeResult<()> {
    loop {
        let packet =
            read_with_controls(stream, config.idle_timeout(), runtime_gate, shutdown).await?;
        if packet.kind != PacketKind::EncryptedFrame {
            return Err(LanRuntimeError::DowngradeAttempt);
        }
        let frame = decode_encrypted_frame(&packet.body)?;
        let now = unix_now()?;
        session.connection.validate_at(now)?;
        let (message, replay) = session.cipher.decrypt(&frame, now)?;
        let result = await_with_controls(
            backend.handle_message(&session.connection, message, replay, now),
            runtime_gate,
            shutdown,
        )
        .await?;
        if let Some(response) = result.response {
            let frame = session.cipher.encrypt(&response, now)?;
            let encoded = encode_encrypted_frame(&frame)?;
            await_with_controls(
                write_packet(
                    stream,
                    PacketKind::EncryptedFrame,
                    &encoded,
                    config.io_timeout(),
                ),
                runtime_gate,
                shutdown,
            )
            .await?;
        }
    }
}

async fn read_with_controls(
    stream: &mut TcpStream,
    deadline: std::time::Duration,
    runtime_gate: &mut watch::Receiver<RuntimeStartupGate>,
    shutdown: &mut watch::Receiver<bool>,
) -> LanRuntimeResult<Packet> {
    await_with_controls(read_packet(stream, deadline), runtime_gate, shutdown).await
}

async fn await_with_controls<F, T>(
    operation: F,
    runtime_gate: &mut watch::Receiver<RuntimeStartupGate>,
    shutdown: &mut watch::Receiver<bool>,
) -> LanRuntimeResult<T>
where
    F: Future<Output = LanRuntimeResult<T>>,
{
    tokio::pin!(operation);
    loop {
        validate_controls(runtime_gate, shutdown)?;
        tokio::select! {
            biased;
            changed = runtime_gate.changed() => {
                if changed.is_err() || runtime_gate.borrow().validate().is_err() {
                    return Err(LanRuntimeError::StartupGateClosed);
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Err(LanRuntimeError::Shutdown);
                }
            }
            result = &mut operation => {
                validate_controls(runtime_gate, shutdown)?;
                return result;
            }
        }
    }
}

fn validate_controls(
    runtime_gate: &watch::Receiver<RuntimeStartupGate>,
    shutdown: &watch::Receiver<bool>,
) -> LanRuntimeResult<()> {
    runtime_gate.borrow().validate()?;
    if *shutdown.borrow() {
        return Err(LanRuntimeError::Shutdown);
    }
    Ok(())
}

fn unix_now() -> LanRuntimeResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| LanRuntimeError::Task)
}
