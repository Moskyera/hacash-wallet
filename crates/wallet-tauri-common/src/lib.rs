#[cfg(all(
    test,
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
mod agent_command_stack_budget;
#[cfg(all(
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
pub mod agent_commands;
#[cfg(all(
    feature = "agent-wallet-testnet-pilot",
    not(any(target_os = "android", target_os = "ios"))
))]
pub mod agent_registry_exit;
#[cfg(all(
    feature = "agent-wallet-testnet-pilot",
    not(any(target_os = "android", target_os = "ios"))
))]
pub mod agent_registry_open;
#[cfg(all(
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
pub mod agent_runtime;
pub mod commands;
#[cfg(all(
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
pub mod companion_backend;
#[cfg(all(
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
pub mod companion_runtime;
pub mod dapp_commands;
pub mod handlers;
pub mod prepared_commands;
pub mod quantum_commands;
pub mod security_commands;
pub mod state;
pub mod update;
pub mod update_commands;
pub mod whisper_commands;

#[cfg(target_os = "android")]
pub mod android_native;
#[cfg(target_os = "android")]
pub mod backup_android;
pub mod backup_commands;
#[cfg(target_os = "android")]
pub mod update_android;

pub mod dapp_approval;
#[cfg(feature = "desktop")]
pub mod desktop_commands;
#[cfg(feature = "desktop")]
pub mod desktop_node;
#[cfg(feature = "desktop")]
pub mod desktop_relay;

#[cfg(all(
    feature = "agent-wallet-admin",
    not(any(target_os = "android", target_os = "ios"))
))]
pub use state::AgentAppState;
pub use state::AppState;
