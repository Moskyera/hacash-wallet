//! Isolated, opt-in local IPC runtime for the independent HPAY Agent Wallet.
//!
//! The crate contains no Tauri, desktop application, Personal Wallet, network
//! listener, HTTP server, TCP server, or L2 dependency.

mod config;
mod error;
mod pairing;
mod pairing_completion;
mod runtime;
mod worker;

pub use config::{
    CanonicalTransportBindingFactory, LocalEndpoint, LocalTransportContext, RuntimeConfig,
    TransportBindingFactory,
};
pub use error::{RuntimeError, RuntimeResult};
pub use pairing::{PairingActivation, PendingPairingView};
pub use runtime::{AgentWalletRuntime, RuntimePhase, RuntimeStatus};

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    #[cfg(windows)]
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use agent_wallet_core::{AgentWalletManager, CreateAgentWallet};
    use hpay_agent_connector::{ConnectorResult, FrameCodec, TransportBinding};

    use super::*;

    #[cfg(windows)]
    static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

    struct TestBindingFactory;

    impl TransportBindingFactory for TestBindingFactory {
        fn create_binding(
            &self,
            context: &LocalTransportContext,
        ) -> ConnectorResult<TransportBinding> {
            Ok(TransportBinding {
                binding_version: 1,
                transport_kind: context.transport_kind().to_owned(),
                connection_id: context.connection_id().clone(),
                peer_identity_sha256: context.peer_identity_sha256().to_owned(),
                transport_transcript_sha256: "cd".repeat(32),
            })
        }
    }

    fn test_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hpay-agent-runtime-{label}-{}", std::process::id()))
    }

    fn config(_root: &std::path::Path, desktop_instance_id: String) -> RuntimeConfig {
        RuntimeConfig {
            desktop_instance_id,
            endpoint: {
                #[cfg(windows)]
                {
                    LocalEndpoint::WindowsNamedPipe {
                        instance_suffix: format!(
                            "{:016x}{:016x}",
                            std::process::id(),
                            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
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
            read_timeout: Duration::from_millis(50),
            write_timeout: Duration::from_millis(50),
            dispatch_timeout: Duration::from_millis(500),
            startup_timeout: Duration::from_secs(2),
            shutdown_timeout: Duration::from_secs(1),
        }
    }

    fn runtime(label: &str) -> (AgentWalletRuntime, std::path::PathBuf) {
        let root = test_root(label);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut manager = AgentWalletManager::open(&root).unwrap();
        let created = manager
            .create_wallet(
                CreateAgentWallet {
                    passphrase: "runtime unit test vault password".to_owned(),
                    network_mode: "testnet".to_owned(),
                    node_url: "http://127.0.0.1:18081".to_owned(),
                    block_one_fingerprint: Some(
                        "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff"
                            .to_owned(),
                    ),
                    mainnet_pilot_acknowledgement: None,
                },
                now,
            )
            .unwrap();
        manager
            .unlock(&created.wallet_id, "runtime unit test vault password", now)
            .unwrap();
        let (desktop_instance_id, server_identity_key) = manager
            .connector_server_identity(&created.wallet_id, now)
            .unwrap();
        let runtime = AgentWalletRuntime::new(
            manager,
            created.wallet_id,
            config(&root, desktop_instance_id),
            server_identity_key,
            Arc::new(TestBindingFactory),
        )
        .unwrap();
        (runtime, root)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_constructor_reuses_the_exact_manager_allocation() {
        let root = test_root("shared-manager");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut manager = AgentWalletManager::open(&root).unwrap();
        let created = manager
            .create_wallet(
                CreateAgentWallet {
                    passphrase: "shared runtime unit test password".to_owned(),
                    network_mode: "testnet".to_owned(),
                    node_url: "http://127.0.0.1:18081".to_owned(),
                    block_one_fingerprint: Some(
                        "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff"
                            .to_owned(),
                    ),
                    mainnet_pilot_acknowledgement: None,
                },
                now,
            )
            .unwrap();
        manager
            .unlock(&created.wallet_id, "shared runtime unit test password", now)
            .unwrap();
        let (desktop_instance_id, server_identity_key) = manager
            .connector_server_identity(&created.wallet_id, now)
            .unwrap();
        let shared = Arc::new(tokio::sync::Mutex::new(manager));
        let runtime = AgentWalletRuntime::new_shared(
            Arc::clone(&shared),
            created.wallet_id,
            config(&root, desktop_instance_id),
            server_identity_key,
            Arc::new(TestBindingFactory),
        )
        .await
        .unwrap();
        assert!(Arc::ptr_eq(&shared, &runtime.manager()));
        drop(runtime);
        drop(shared);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transport_payload_bridge_adds_and_removes_exactly_one_prefix() {
        let codec = FrameCodec::default();
        let payload = br#"{"type":"disconnect"}"#;
        let framed = crate::worker::transport_payload_to_server_frame(&codec, payload).unwrap();
        assert_eq!(
            u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize,
            payload.len()
        );
        assert_eq!(
            crate::worker::server_frame_to_transport_payload(&codec, &framed).unwrap(),
            payload
        );
    }

    #[test]
    fn manifest_keeps_the_runtime_dependency_boundary() {
        let manifest = include_str!("../Cargo.toml");
        for forbidden in [
            "tauri",
            "wallet-tauri-common",
            "hacash-wallet-core",
            "l2-fast-pay-hub",
            "axum",
            "reqwest",
        ] {
            assert!(
                !manifest.contains(forbidden),
                "forbidden dependency found: {forbidden}"
            );
        }
    }

    #[cfg(not(feature = "listener"))]
    #[test]
    fn listener_requires_explicit_compile_time_opt_in() {
        let (runtime, root) = runtime("disabled");
        assert_eq!(runtime.start(), Err(RuntimeError::ListenerDisabled));
        assert_eq!(runtime.status().phase, RuntimePhase::Stopped);
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "listener")]
    #[test]
    fn listener_stops_cleanly_and_restarts_with_the_same_injected_identity() {
        let (runtime, root) = runtime("restart");
        let pinned_identity = runtime.pinned_server_identity().unwrap();
        runtime.start().unwrap();
        assert_eq!(runtime.status().phase, RuntimePhase::Running);
        assert_eq!(runtime.start(), Err(RuntimeError::AlreadyRunning));
        runtime.stop().unwrap();
        assert_eq!(runtime.status().phase, RuntimePhase::Stopped);
        runtime.start().unwrap();
        assert_eq!(runtime.status().phase, RuntimePhase::Running);
        assert_eq!(runtime.pinned_server_identity().unwrap(), pinned_identity);
        runtime.stop().unwrap();
        assert_eq!(runtime.stop(), Err(RuntimeError::NotRunning));
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "listener")]
    #[tokio::test(flavor = "current_thread")]
    async fn isolated_worker_does_not_occupy_the_callers_executor() {
        let (runtime, root) = runtime("isolated");
        runtime.start().unwrap();
        let manager = runtime.manager();
        let guard = tokio::time::timeout(Duration::from_millis(100), manager.lock())
            .await
            .expect("worker must not block the caller executor");
        drop(guard);
        runtime.stop().unwrap();
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
    }
}
