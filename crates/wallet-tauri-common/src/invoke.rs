use tauri::{Runtime, ipc::Invoke};

/// Wraps a Tauri invoke handler.
///
/// **Do not use `catch_unwind` here on Android.** Tauri's JNI entry
/// (`Java_*_Rust_ipc`) is nounwind; panicking/unwinding across that boundary
/// aborts with `panic_cannot_unwind` / SIGABRT (seen on v0.1.48 APK).
///
/// Real command failures must return `Result::Err` / `resolver.reject`, not panic.
/// This helper exists only as a stable call-site name; it does not catch panics.
pub fn invoke_with_panic_boundary<R, F>(
    handler: F,
    _boundary: &'static str,
) -> impl Fn(Invoke<R>) -> bool + Send + Sync + 'static
where
    R: Runtime,
    F: Fn(Invoke<R>) -> bool + Send + Sync + 'static,
{
    handler
}
