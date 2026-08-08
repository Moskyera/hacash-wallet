use std::time::Duration;

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, RunEvent, Runtime, WindowEvent};

use super::AgentCompanionMobileState;

const AGENT_COMPANION_WEBVIEW: &str = "agent-companion";
const LEASE_WATCH_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("agent-companion-lifecycle")
        .setup(|app, _api| {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(LEASE_WATCH_INTERVAL);
                loop {
                    interval.tick().await;
                    if let Some(state) = app.try_state::<AgentCompanionMobileState>() {
                        state.expire_session_lease().await;
                    }
                }
            });
            Ok(())
        })
        .on_event(|app, event| {
            if should_close(event) {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(state) = app.try_state::<AgentCompanionMobileState>() {
                        state.close_native_session().await;
                    }
                });
            }
        })
        .on_drop(|app| {
            tauri::async_runtime::spawn(async move {
                if let Some(state) = app.try_state::<AgentCompanionMobileState>() {
                    state.close_native_session().await;
                }
            });
        })
        .build()
}

fn should_close(event: &RunEvent) -> bool {
    if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
        return true;
    }
    if let RunEvent::WindowEvent { label, event, .. } = event {
        return should_close_window(label, event);
    }
    false
}

fn should_close_window(label: &str, event: &WindowEvent) -> bool {
    if label == AGENT_COMPANION_WEBVIEW && matches!(event, WindowEvent::Destroyed) {
        return true;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if matches!(event, WindowEvent::Suspended) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_and_companion_destroy_are_native_close_events() {
        assert!(should_close(&RunEvent::Exit));
        assert!(should_close_window(
            "agent-companion",
            &WindowEvent::Destroyed
        ));
        assert!(!should_close_window("main", &WindowEvent::Destroyed));
    }
}
