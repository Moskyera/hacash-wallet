pub mod commands;
pub mod dapp_commands;
pub mod handlers;
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
pub mod desktop_relay;

pub use state::AppState;
