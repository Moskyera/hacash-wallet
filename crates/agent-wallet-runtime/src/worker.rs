use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use agent_wallet_core::{AgentWalletId, AgentWalletManager};
use hpay_agent_connector::{
    ConnectionServer, ConnectorError, ConnectorResult, FrameCodec, PairingAcknowledgement,
    PairingClientEnvelope, PairingPayloadClassification, ServerIdentityKey,
};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::config::{
    LocalEndpoint, RuntimeConfig, TransportBindingFactory, create_transport_binding,
};
use crate::error::{RuntimeError, RuntimeResult};
use crate::pairing::{SharedPairingState, process_pairing_envelope, unix_now};

const MAX_FRAMES_PER_CONNECTION: usize = 32;

#[derive(Default)]
struct ConnectionFrameBudget {
    served: usize,
}

impl ConnectionFrameBudget {
    fn has_capacity(&self) -> bool {
        self.served < MAX_FRAMES_PER_CONNECTION
    }

    fn consume(&mut self) -> RuntimeResult<()> {
        if !self.has_capacity() {
            return Err(RuntimeError::ConnectionBudgetExhausted);
        }
        self.served = self
            .served
            .checked_add(1)
            .ok_or(RuntimeError::ConnectionBudgetExhausted)?;
        Ok(())
    }
}

pub(crate) struct WorkerInputs {
    pub wallet_id: AgentWalletId,
    pub manager: Arc<Mutex<AgentWalletManager>>,
    pub config: RuntimeConfig,
    pub server_identity_key: Arc<ServerIdentityKey>,
    pub binding_factory: Arc<dyn TransportBindingFactory>,
    pub pairing_state: SharedPairingState,
    pub shutdown: Arc<AtomicBool>,
    pub startup: mpsc::SyncSender<RuntimeResult<String>>,
}

pub(crate) fn run(inputs: WorkerInputs) -> RuntimeResult<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
    run_platform(inputs, &runtime)
}

trait RuntimeConnection {
    fn peer_identity_sha256(&self) -> &str;

    fn read_payload(&mut self, codec: &FrameCodec, timeout: Duration) -> ConnectorResult<Vec<u8>>;
    fn write_payload(
        &mut self,
        codec: &FrameCodec,
        payload: &[u8],
        timeout: Duration,
    ) -> ConnectorResult<()>;
}

#[cfg(windows)]
impl RuntimeConnection
    for hpay_agent_connector::transport::windows::WindowsNamedPipeConnection<'_>
{
    fn peer_identity_sha256(&self) -> &str {
        self.peer_identity_sha256()
    }

    fn read_payload(&mut self, codec: &FrameCodec, timeout: Duration) -> ConnectorResult<Vec<u8>> {
        self.read_frame(codec, timeout)
    }

    fn write_payload(
        &mut self,
        codec: &FrameCodec,
        payload: &[u8],
        timeout: Duration,
    ) -> ConnectorResult<()> {
        self.write_frame(codec, payload, timeout)
    }
}

#[cfg(unix)]
impl RuntimeConnection for hpay_agent_connector::transport::unix::UnixConnectorConnection {
    fn peer_identity_sha256(&self) -> &str {
        self.peer_identity_sha256()
    }

    fn read_payload(&mut self, codec: &FrameCodec, timeout: Duration) -> ConnectorResult<Vec<u8>> {
        self.read_frame(codec, timeout)
    }

    fn write_payload(
        &mut self,
        codec: &FrameCodec,
        payload: &[u8],
        timeout: Duration,
    ) -> ConnectorResult<()> {
        self.write_frame(codec, payload, timeout)
    }
}

fn serve_connection<C: RuntimeConnection>(
    connection: &mut C,
    endpoint_label: &str,
    inputs: &WorkerInputs,
    runtime: &tokio::runtime::Runtime,
) -> RuntimeResult<()> {
    let codec = FrameCodec::new(inputs.config.max_frame_bytes)?;
    let first_payload = match connection.read_payload(&codec, inputs.config.read_timeout) {
        Ok(payload) => payload,
        Err(ConnectorError::Expired | ConnectorError::Io) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    match PairingClientEnvelope::classify_payload(&first_payload) {
        PairingPayloadClassification::Valid(envelope) => {
            if inputs.shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            let response = runtime.block_on(process_pairing_envelope(
                &inputs.pairing_state,
                inputs.manager.as_ref(),
                &inputs.wallet_id,
                envelope,
                inputs.server_identity_key.as_ref(),
                unix_now()?,
            ))?;
            if inputs.shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            let response_payload = response.to_payload()?;
            connection.write_payload(&codec, &response_payload, inputs.config.write_timeout)?;
            if inputs.shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            let acknowledgement_payload =
                connection.read_payload(&codec, inputs.config.read_timeout)?;
            PairingAcknowledgement::from_payload(&acknowledgement_payload)?
                .verify_response(&response.request_id, &response_payload)?;
            return Ok(());
        }
        PairingPayloadClassification::Invalid(error) => return Err(error.into()),
        PairingPayloadClassification::NotPairing => {}
    }

    let transport_binding = create_transport_binding(
        inputs.binding_factory.as_ref(),
        &inputs.config.endpoint,
        endpoint_label.to_owned(),
        connection.peer_identity_sha256().to_owned(),
    )?;
    let mut server = ConnectionServer::new(
        inputs.config.desktop_instance_id.clone(),
        inputs.server_identity_key.as_ref(),
        transport_binding,
        inputs.config.max_frame_bytes,
    )?;

    let mut next_payload = Some(first_payload);
    let mut frame_budget = ConnectionFrameBudget::default();
    while !inputs.shutdown.load(Ordering::Acquire) && frame_budget.has_capacity() {
        let payload = if let Some(payload) = next_payload.take() {
            payload
        } else {
            match connection.read_payload(&codec, inputs.config.read_timeout) {
                Ok(payload) => payload,
                Err(ConnectorError::Expired | ConnectorError::Io) => break,
                Err(error) => return Err(error.into()),
            }
        };
        frame_budget.consume()?;
        if inputs.shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let framed_request = transport_payload_to_server_frame(&codec, &payload)?;
        let now_unix = unix_now()?;
        let output = runtime.block_on(async {
            let mut manager = inputs.manager.lock().await;
            if inputs.shutdown.load(Ordering::Acquire) {
                return Ok::<_, RuntimeError>(None);
            }
            let output = tokio::time::timeout(
                inputs.config.dispatch_timeout,
                server.handle_frame(&framed_request, now_unix, &mut *manager),
            )
            .await
            .map_err(|_| RuntimeError::DispatchTimeout)?;
            if inputs.shutdown.load(Ordering::Acquire) {
                Ok(None)
            } else {
                Ok(Some(output))
            }
        })?;
        let Some(output) = output else {
            return Ok(());
        };
        if inputs.shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let response_payload = server_frame_to_transport_payload(&codec, &output.frame)?;
        connection.write_payload(&codec, &response_payload, inputs.config.write_timeout)?;
        if output.close_connection || !frame_budget.has_capacity() {
            break;
        }
    }
    Ok(())
}

pub(crate) fn transport_payload_to_server_frame(
    codec: &FrameCodec,
    payload: &[u8],
) -> ConnectorResult<Vec<u8>> {
    codec.encode(payload)
}

pub(crate) fn server_frame_to_transport_payload(
    codec: &FrameCodec,
    frame: &[u8],
) -> ConnectorResult<Vec<u8>> {
    codec.decode_exact(frame)
}

#[cfg(windows)]
fn run_platform(inputs: WorkerInputs, runtime: &tokio::runtime::Runtime) -> RuntimeResult<()> {
    use hpay_agent_connector::transport::ListenerPolicy;
    use hpay_agent_connector::transport::windows::{
        WindowsNamedPipeConfig, WindowsNamedPipeListener,
    };

    let LocalEndpoint::WindowsNamedPipe { instance_suffix } = &inputs.config.endpoint;
    let mut config = WindowsNamedPipeConfig::for_current_process(instance_suffix)?;
    config.policy = ListenerPolicy { enabled: true };
    let mut listener = match WindowsNamedPipeListener::bind(&config) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = inputs.startup.send(Err(error.clone().into()));
            return Err(error.into());
        }
    };
    let endpoint_label = listener.pipe_name().to_owned();
    let _ = inputs.startup.send(Ok(endpoint_label.clone()));
    info!(
        endpoint = endpoint_label,
        "agent wallet named-pipe runtime started"
    );

    while !inputs.shutdown.load(Ordering::Acquire) {
        match listener.accept_timeout(inputs.config.accept_timeout) {
            Ok(mut connection) => {
                if let Err(error) =
                    serve_connection(&mut connection, &endpoint_label, &inputs, runtime)
                {
                    warn!(%error, "agent wallet connection closed after an error");
                }
            }
            Err(ConnectorError::Expired) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn run_platform(inputs: WorkerInputs, runtime: &tokio::runtime::Runtime) -> RuntimeResult<()> {
    use hpay_agent_connector::transport::ListenerPolicy;
    use hpay_agent_connector::transport::unix::{UnixConnectorListener, UnixTransportConfig};

    let LocalEndpoint::UnixDomainSocket { socket_path } = &inputs.config.endpoint;
    let mut transport_config = UnixTransportConfig::for_current_user(socket_path.clone());
    transport_config.policy = ListenerPolicy { enabled: true };
    let listener = match UnixConnectorListener::bind(transport_config) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = inputs.startup.send(Err(error.clone().into()));
            return Err(error.into());
        }
    };
    let endpoint_label = listener.local_path().display().to_string();
    let _ = inputs.startup.send(Ok(endpoint_label.clone()));
    info!(
        endpoint = endpoint_label,
        "agent wallet UDS runtime started"
    );

    while !inputs.shutdown.load(Ordering::Acquire) {
        match listener.accept_timeout(inputs.config.accept_timeout) {
            Ok(mut connection) => {
                if let Err(error) =
                    serve_connection(&mut connection, &endpoint_label, &inputs, runtime)
                {
                    warn!(%error, "agent wallet connection closed after an error");
                }
            }
            Err(ConnectorError::Expired) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn run_platform(inputs: WorkerInputs, _runtime: &tokio::runtime::Runtime) -> RuntimeResult<()> {
    let error = RuntimeError::Connector(ConnectorError::PlatformUnavailable);
    let _ = inputs.startup.send(Err(error.clone()));
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_connection_has_an_exact_fairness_budget() {
        let mut budget = ConnectionFrameBudget::default();
        for _ in 0..MAX_FRAMES_PER_CONNECTION {
            assert!(budget.has_capacity());
            budget.consume().unwrap();
        }
        assert!(!budget.has_capacity());
        assert_eq!(
            budget.consume(),
            Err(RuntimeError::ConnectionBudgetExhausted)
        );
    }
}
