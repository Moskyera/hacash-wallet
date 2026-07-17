use tauri::{Runtime, ipc::Invoke};

/// Catches panics raised while Tauri synchronously dispatches an IPC command.
/// Async command futures run after dispatch and are intentionally outside this boundary.
pub fn invoke_with_panic_boundary<R, F>(
    handler: F,
    boundary: &'static str,
) -> impl Fn(Invoke<R>) -> bool + Send + Sync + 'static
where
    R: Runtime,
    F: Fn(Invoke<R>) -> bool + Send + Sync + 'static,
{
    move |invoke: Invoke<R>| {
        let command = invoke.message.command().to_owned();
        let resolver = invoke.resolver.clone();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(invoke))) {
            Ok(handled) => handled,
            Err(_) => {
                tracing::error!(boundary, command = %command, "caught panic during synchronous IPC dispatch");
                resolver.reject(format!(
                    "Internal wallet error in {command}. Retry once and report this command if it repeats."
                ));
                true
            }
        }
    }
}
