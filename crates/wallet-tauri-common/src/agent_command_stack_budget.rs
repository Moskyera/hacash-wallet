//! A ceiling on how big a spawned Tauri command future is allowed to get.
//!
//! # Why this file exists
//!
//! This is the layer that actually killed the wallet. On 2026-08-29 the owner
//! pressed "Confirm exact setup" on the first mainnet Fast Pay channel and
//! `hacash-wallet.exe` died with `0xC00000FD` (`STACK_OVERFLOW`), faulting
//! inside `_alloca_probe`, the MSVC probe emitted for a function reserving a
//! large frame. Not recursion. Four enormous frames.
//!
//! `#[tauri::command] pub async fn` compiles to
//! `InvokeResolver::respond_async_serialized`, which calls
//! `tauri::async_runtime::spawn`, which calls `tokio::task::spawn`. Those are
//! plain synchronous calls, made on the thread that dispatched the IPC
//! message, before the runtime ever sees the future, and each one takes the
//! future by value. Decoding the `mov eax, imm32` before every `_alloca_probe`
//! call in the shipped `hacash-wallet.exe` gives the multipliers:
//!
//! ```text
//!   respond_async_serialized     6.02 x this future
//!   tauri::async_runtime::spawn 12.04 x this future
//!   tokio::task::spawn::spawn    6.02 x this future
//!   plus a constant 261,832-byte generate_handler! dispatch frame
//! ```
//!
//! At 75,656 bytes, `agent_wallet_confirm_fast_pay_channel_setup` therefore
//! reserved 2,083,888 bytes across four live frames. The dispatching thread is
//! the WebView2 UI thread, and the exe's PE header says
//! `SizeOfStackReserve = 1,048,576`. It could not have fitted, on any machine,
//! on any run.
//!
//! # What is being asserted
//!
//! One byte here is about twenty-four bytes of stack on a 1 MiB thread. This
//! test is the budget that turns that exchange rate into a build failure
//! instead of a crash on a money path.
//!
//! # If this fails
//!
//! Do NOT raise `MAX_COMMAND_FUTURE_BYTES`. A failure means a command grew a
//! state machine the release binary will reserve two dozen times over on a
//! stack that cannot hold it. The wallet survived this class of bug once only
//! because the overflow landed BEFORE the durable `SignatureMayExist` marker,
//! so nothing was signed and no money moved. Land it after that marker and the
//! wallet refuses by design to sign the same operation twice, and a funded
//! channel is left with no unilateral exit.
//!
//! The fix is to move the offending body to the heap. Prefer doing it in
//! `agent-wallet-core`, by making the public `async fn` a thin
//! `Box::pin(self.<name>_inner(..)).await` wrapper: that shrinks the command
//! future here and protects every other caller at the same time. See
//! `agent-wallet-core/src/service/l2/stack_budget.rs`.

/// Ceiling on any single spawned Tauri command future, in bytes.
///
/// Derived from the crash, not from taste:
///
/// * 1,048,576 bytes of stack reserve on the dispatching thread
/// * minus the constant 261,832-byte `generate_handler!` dispatch frame
/// * leaves 786,744 bytes to be divided by the 24.1x spawn plumbing
/// * 786,744 / 24.1 = 32,645 bytes of command future before the wallet dies
///
/// 16 KiB is half of that. The other half is margin, and the margin has a job:
/// the WebView2 message pump has already consumed unknown depth before the
/// dispatch frame is entered, and a build with different inlining moves these
/// numbers around.
///
/// `agent_wallet_confirm_fast_pay_channel_setup` was 75,656 bytes when it
/// killed the wallet.
const MAX_COMMAND_FUTURE_BYTES: usize = 16 * 1024;

/// Returns `size_of` the future the closure would return. The closure is never
/// called, so no `AgentAppState`, `Webview` or manager is ever constructed and
/// nothing touches the owner's wallet data.
fn future_size<A, F, Fut>(_never_called: F) -> usize
where
    F: FnOnce(A) -> Fut,
    Fut: core::future::Future,
{
    core::mem::size_of::<Fut>()
}

/// Every command in `agent_commands` that the desktop shell can invoke, with
/// the size of the future `tokio::task::spawn` will be handed.
///
/// A command missing from this list is a command with no budget. Add new ones.
fn measured_command_futures() -> Vec<(&'static str, usize)> {
    use crate::agent_commands as c;
    use crate::state::AgentAppState;
    use tauri::Webview;

    type Ctx<'a> = (Webview, tauri::State<'a, AgentAppState>);

    vec![
        (
            "agent_wallet_runtime_status",
            future_size(|(w, s): Ctx<'_>| c::agent_wallet_runtime_status(w, s)),
        ),
        (
            "agent_wallet_overview",
            future_size(|(w, s): Ctx<'_>| c::agent_wallet_overview(String::new(), w, s)),
        ),
        (
            "agent_wallet_list_activity",
            future_size(|(w, s): Ctx<'_>| c::agent_wallet_list_activity(String::new(), w, s)),
        ),
        (
            "agent_wallet_unlock",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_unlock(String::new(), String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_prepare_fast_pay_channel",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_prepare_fast_pay_channel(
                    String::new(),
                    String::new(),
                    String::new(),
                    w,
                    s,
                )
            }),
        ),
        (
            "agent_wallet_confirm_fast_pay_channel_setup",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_confirm_fast_pay_channel_setup(
                    String::new(),
                    String::new(),
                    String::new(),
                    w,
                    s,
                )
            }),
        ),
        (
            "agent_wallet_recover_fast_pay_channel_setup",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_recover_fast_pay_channel_setup(String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_prepare_fast_pay_channel_close",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_prepare_fast_pay_channel_close(String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_confirm_fast_pay_channel_close",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_confirm_fast_pay_channel_close(
                    String::new(),
                    String::new(),
                    String::new(),
                    w,
                    s,
                )
            }),
        ),
        (
            "agent_wallet_recover_fast_pay_channel_close",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_recover_fast_pay_channel_close(String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_fast_pay_channel_voucher",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_fast_pay_channel_voucher(String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_take_fast_pay_channel_voucher",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_take_fast_pay_channel_voucher(String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_broadcast_fast_pay_channel_voucher",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_broadcast_fast_pay_channel_voucher(String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_execute_approved_fast_pay",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_execute_approved_fast_pay(String::new(), String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_bind_hvm_channel",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_bind_hvm_channel(String::new(), String::new(), String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_execute_approved_hvm",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_execute_approved_hvm(String::new(), String::new(), w, s)
            }),
        ),
        (
            "agent_wallet_pilot_diagnostics_preview",
            future_size(|(w, s): Ctx<'_>| {
                c::agent_wallet_pilot_diagnostics_preview(String::new(), w, s)
            }),
        ),
    ]
}

/// The budget, asserted over every spawned Agent Wallet command.
///
/// Read the module comment before changing `MAX_COMMAND_FUTURE_BYTES`. The
/// answer to a failure here is `Box::pin`, not a bigger number.
#[test]
fn spawned_command_futures_stay_within_the_stack_budget() {
    // 1 MiB of thread stack, minus the constant dispatch frame, divided by the
    // multiplier measured in the shipped binary. Reported alongside each
    // failure so the next reader sees the stack cost, not just a byte count.
    const SPAWN_MULTIPLIER: f64 = 24.1;
    const DISPATCH_FRAME_BYTES: u64 = 261_832;
    const THREAD_STACK_RESERVE_BYTES: u64 = 1_048_576;

    let mut over = Vec::new();
    for (name, size) in measured_command_futures() {
        let stack = DISPATCH_FRAME_BYTES + (size as f64 * SPAWN_MULTIPLIER) as u64;
        println!("{size:>8}  ->{stack:>9} bytes of stack   {name}");
        if size > MAX_COMMAND_FUTURE_BYTES {
            over.push(format!(
                "{name} is {size} bytes, over the {MAX_COMMAND_FUTURE_BYTES}-byte budget; \
                 the release binary reserves about {stack} bytes of stack for it, against \
                 {THREAD_STACK_RESERVE_BYTES} available"
            ));
        }
    }
    assert!(
        over.is_empty(),
        "spawned command futures exceeded the stack budget; move the body to the heap with \
         Box::pin, do not raise the constant (see the module comment in \
         agent_command_stack_budget.rs):\n  {}",
        over.join("\n  ")
    );
}
